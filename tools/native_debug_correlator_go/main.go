package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultShardSize = 5000

type appError struct {
	reasonCode string
	message    string
}

func newAppError(reasonCode string, message string) *appError {
	return &appError{
		reasonCode: reasonCode,
		message:    message,
	}
}

func (err *appError) Error() string {
	return err.message
}

type request struct {
	SchemaVersion       int64    `json:"schema_version"`
	DebugTypesPaths     []string `json:"debug_types_paths"`
	DebugFunctionsPaths []string `json:"debug_functions_paths"`
	DebugTypes          []any    `json:"debug_types"`
	DebugFunctions      []any    `json:"debug_functions"`
	OutputDir           *string  `json:"output_dir"`
	ShardSize           *int     `json:"shard_size"`
	DumpFiles           *bool    `json:"dump_files"`
	OutDir              *string  `json:"out_dir"`
}

type counters struct {
	ParsedTypes         int `json:"parsed_types"`
	ParsedFunctions     int `json:"parsed_functions"`
	DedupedFunctions    int `json:"deduped_functions"`
	WrittenRecords      int `json:"written_records"`
	UpdatedFunctions    int `json:"updated_functions"`
	CorrelatedFunctions int `json:"correlated_functions"`
	Shards              int `json:"shards"`
}

type artifacts struct {
	CorrelatedShards      []string `json:"correlated_shards"`
	AllFriendlyDebugTypes *string  `json:"all_friendly_debug_types,omitempty"`
}

type timings struct {
	ParseMS     uint64 `json:"parse_ms"`
	DedupeMS    uint64 `json:"dedupe_ms"`
	CorrelateMS uint64 `json:"correlate_ms"`
	WriteMS     uint64 `json:"write_ms"`
	TotalMS     uint64 `json:"total_ms"`
}

type response struct {
	SchemaVersion int64     `json:"schema_version"`
	Status        string    `json:"status"`
	Counters      counters  `json:"counters"`
	Artifacts     artifacts `json:"artifacts"`
	Timings       timings   `json:"timings"`
	ReasonCode    *string   `json:"reason_code,omitempty"`
}

type typeEntry struct {
	Addr           string
	Tag            string
	Name           string
	BaseTypeAddr   string
	BaseTypeString string
	ConstSize      int64
	Scope          string
	EnumElems      any
	RawDebugInfo   map[string]any
}

type typeIndex struct {
	entries   map[string]typeEntry
	addrOrder []string
}

type functionEntry struct {
	OriginalRowIdx int
	FileLocation   string
	TypeArguments  []string
}

type functionSignatureElems struct {
	ReturnType any        `json:"return_type"`
	Params     [][]string `json:"params"`
}

type sourceLocation struct {
	SourceFile string `json:"source_file"`
	SourceLine string `json:"source_line"`
}

type correlatedRecord struct {
	RowIdx             int                    `json:"row_idx"`
	FuncSignatureElems functionSignatureElems `json:"func_signature_elems"`
	Source             sourceLocation         `json:"source"`
}

type correlationWriteResult struct {
	CorrelatedShards []string
	WrittenRecords   int
	CorrelateMS      uint64
	WriteMS          uint64
}

type memberEntry struct {
	Addr         string
	ElemName     string
	BaseTypeAddr string
}

type indexedCorrelatedRecord struct {
	chunkOffset int
	record      correlatedRecord
}

func toMS(duration time.Duration) uint64 {
	return uint64(duration.Milliseconds())
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func availableWorkerCount() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	return workers
}

func asString(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}

func normalizeSignedDecimal(text string) (string, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "", false
	}

	bigInt := new(big.Int)
	if _, ok := bigInt.SetString(trimmed, 10); !ok {
		return "", false
	}
	return bigInt.String(), true
}

func parseIntString(value any) (string, bool) {
	switch typed := value.(type) {
	case json.Number:
		return normalizeSignedDecimal(typed.String())
	case string:
		return normalizeSignedDecimal(typed)
	case int:
		return strconv.FormatInt(int64(typed), 10), true
	case int8:
		return strconv.FormatInt(int64(typed), 10), true
	case int16:
		return strconv.FormatInt(int64(typed), 10), true
	case int32:
		return strconv.FormatInt(int64(typed), 10), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case uint:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint8:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint16:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint32:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint64:
		return strconv.FormatUint(typed, 10), true
	case float32:
		floatValue := float64(typed)
		if math.IsNaN(floatValue) || math.IsInf(floatValue, 0) || math.Trunc(floatValue) != floatValue {
			return "", false
		}
		if floatValue < math.MinInt64 || floatValue > math.MaxInt64 {
			return "", false
		}
		return strconv.FormatInt(int64(floatValue), 10), true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed {
			return "", false
		}
		if typed < math.MinInt64 || typed > math.MaxInt64 {
			return "", false
		}
		return strconv.FormatInt(int64(typed), 10), true
	default:
		return "", false
	}
}

func parseInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case float32:
		floatValue := float64(typed)
		if math.IsNaN(floatValue) || math.IsInf(floatValue, 0) || math.Trunc(floatValue) != floatValue {
			return 0, false
		}
		if floatValue < math.MinInt64 || floatValue > math.MaxInt64 {
			return 0, false
		}
		return int64(floatValue), true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed {
			return 0, false
		}
		if typed < math.MinInt64 || typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return parsed, true
		}
		parsed, err = strconv.ParseInt(strings.TrimSpace(typed.String()), 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func isZeroTypeKey(value string) bool {
	if value == "" {
		return true
	}
	normalized, ok := normalizeSignedDecimal(value)
	if !ok {
		return false
	}
	return normalized == "0"
}

func extractSchemaVersion(rawPayload []byte) int64 {
	decoder := json.NewDecoder(bytes.NewReader(rawPayload))
	decoder.UseNumber()

	payload := map[string]any{}
	if err := decoder.Decode(&payload); err != nil {
		return 0
	}

	value, ok := payload["schema_version"]
	if !ok {
		return 0
	}
	parsed, ok := parseInt64(value)
	if !ok {
		return 0
	}
	return parsed
}

func parseRequest(rawPayload []byte) (request, error) {
	decoder := json.NewDecoder(bytes.NewReader(rawPayload))
	decoder.UseNumber()

	var parsedRequest request
	if err := decoder.Decode(&parsedRequest); err != nil {
		return request{}, err
	}
	return parsedRequest, nil
}

func normalizeYAML(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = normalizeYAML(item)
		}
		return result
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[fmt.Sprint(key)] = normalizeYAML(item)
		}
		return result
	case []any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, normalizeYAML(item))
		}
		return result
	default:
		return typed
	}
}

func normalizeRecords(value any, out *[]any) {
	switch typed := value.(type) {
	case nil:
		return
	case []any:
		*out = append(*out, typed...)
	case map[string]any:
		if itemsValue, ok := typed["items"]; ok {
			if items, ok := itemsValue.([]any); ok {
				*out = append(*out, items...)
				return
			}
		}
		*out = append(*out, typed)
	default:
		return
	}
}

func parseRecordsFromFile(path string) ([]any, *appError) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, newAppError("io_error", fmt.Sprintf("failed reading %s: %v", path, err))
	}
	if strings.TrimSpace(string(content)) == "" {
		return []any{}, nil
	}

	ndjsonRecords := make([]any, 0)
	ndjsonMode := false
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			ndjsonMode = false
			ndjsonRecords = nil
			break
		}

		ndjsonMode = true
		normalizeRecords(value, &ndjsonRecords)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, newAppError("io_error", fmt.Sprintf("failed scanning %s: %v", path, scanErr))
	}
	if ndjsonMode {
		return ndjsonRecords, nil
	}

	var parsed any
	if err := yaml.Unmarshal(content, &parsed); err != nil {
		return nil, newAppError("parse_error", fmt.Sprintf("failed parsing YAML/JSON in %s: %v", path, err))
	}

	records := make([]any, 0)
	normalizeRecords(normalizeYAML(parsed), &records)
	return records, nil
}

type indexedParsedRecords struct {
	pathIdx int
	records []any
	err     *appError
}

func loadRecordsFromPaths(paths []string) ([]any, *appError) {
	if len(paths) == 0 {
		return []any{}, nil
	}

	workerCount := minInt(availableWorkerCount(), len(paths))
	if workerCount <= 1 {
		merged := make([]any, 0)
		for _, path := range paths {
			records, err := parseRecordsFromFile(path)
			if err != nil {
				return nil, err
			}
			merged = append(merged, records...)
		}
		return merged, nil
	}

	perFile := make([][]any, len(paths))
	jobs := make(chan int)
	results := make(chan indexedParsedRecords, len(paths))

	var workers sync.WaitGroup
	for workerIdx := 0; workerIdx < workerCount; workerIdx++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for pathIdx := range jobs {
				records, err := parseRecordsFromFile(paths[pathIdx])
				results <- indexedParsedRecords{
					pathIdx: pathIdx,
					records: records,
					err:     err,
				}
			}
		}()
	}

	go func() {
		for pathIdx := range paths {
			jobs <- pathIdx
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()

	var firstErr *appError
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		perFile[result.pathIdx] = result.records
	}
	if firstErr != nil {
		return nil, firstErr
	}

	merged := make([]any, 0)
	for _, records := range perFile {
		merged = append(merged, records...)
	}
	return merged, nil
}

func shallowCopyMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func parseTypeEntry(record any) *typeEntry {
	object, ok := record.(map[string]any)
	if !ok {
		return nil
	}

	addr, ok := parseIntString(object["addr"])
	if !ok {
		return nil
	}

	rawDebugInfo := shallowCopyMap(object)
	name := asString(object["name"])
	if name == "_Bool" {
		name = "bool"
		rawDebugInfo["name"] = name
	}

	baseTypeAddr := "0"
	if parsedBaseTypeAddr, ok := parseIntString(object["base_type_addr"]); ok {
		baseTypeAddr = parsedBaseTypeAddr
	}

	constSize := int64(0)
	if parsedConstSize, ok := parseInt64(object["const_size"]); ok {
		constSize = parsedConstSize
	}

	scope := "0"
	if parsedScope, ok := parseIntString(object["scope"]); ok {
		scope = parsedScope
	}

	enumElems, ok := object["enum_elems"]
	if !ok {
		enumElems = []any{}
	}

	return &typeEntry{
		Addr:           addr,
		Tag:            asString(object["tag"]),
		Name:           name,
		BaseTypeAddr:   baseTypeAddr,
		BaseTypeString: asString(object["base_type_string"]),
		ConstSize:      constSize,
		Scope:          scope,
		EnumElems:      enumElems,
		RawDebugInfo:   rawDebugInfo,
	}
}

func parseFunctionEntry(record any, originalRowIdx int) *functionEntry {
	object, ok := record.(map[string]any)
	if !ok {
		return nil
	}

	typeArguments := make([]string, 0)
	rawTypeArguments, ok := object["type_arguments"].([]any)
	if ok {
		for _, argument := range rawTypeArguments {
			if parsedArgument, ok := parseIntString(argument); ok {
				typeArguments = append(typeArguments, parsedArgument)
			}
		}
	}

	return &functionEntry{
		OriginalRowIdx: originalRowIdx,
		FileLocation:   asString(object["file_location"]),
		TypeArguments:  typeArguments,
	}
}

func buildTypeIndex(records []any) typeIndex {
	index := typeIndex{
		entries:   make(map[string]typeEntry),
		addrOrder: make([]string, 0),
	}

	for _, record := range records {
		entry := parseTypeEntry(record)
		if entry == nil {
			continue
		}

		if _, exists := index.entries[entry.Addr]; !exists {
			index.addrOrder = append(index.addrOrder, entry.Addr)
		}
		index.entries[entry.Addr] = *entry
	}

	return index
}

func correlationCacheKey(function functionEntry) string {
	if len(function.TypeArguments) == 0 {
		return function.FileLocation
	}
	return function.FileLocation + "\x1f" + strings.Join(function.TypeArguments, ",")
}

func buildCorrelationPlan(functions []functionEntry) ([]functionEntry, []int) {
	uniqueFunctions := make([]functionEntry, 0, len(functions))
	rowToUniqueIdx := make([]int, 0, len(functions))
	keyToUniqueIdx := make(map[string]int, len(functions))

	for _, function := range functions {
		key := correlationCacheKey(function)
		uniqueIdx, exists := keyToUniqueIdx[key]
		if !exists {
			uniqueIdx = len(uniqueFunctions)
			uniqueFunctions = append(uniqueFunctions, function)
			keyToUniqueIdx[key] = uniqueIdx
		}
		rowToUniqueIdx = append(rowToUniqueIdx, uniqueIdx)
	}

	return uniqueFunctions, rowToUniqueIdx
}

func extractFuncSigFriendlyTypeTags(targetType string, typeMap map[string]typeEntry) []string {
	if isZeroTypeKey(targetType) {
		return []string{"void"}
	}

	tags := make([]string, 0)
	typeToQuery := targetType
	visited := make(map[string]struct{})

	for {
		if _, seen := visited[typeToQuery]; seen {
			tags = append(tags, "Infinite loop")
			break
		}

		target, ok := typeMap[typeToQuery]
		if !ok {
			tags = append(tags, "N/A")
			break
		}

		tags = append(tags, target.Tag)
		if strings.Contains(target.Tag, "array") {
			tags = append(tags, fmt.Sprintf("ARRAY-SIZE: %d", target.ConstSize))
		}

		if target.Name != "" {
			tags = append(tags, target.Name)
			break
		}

		if target.BaseTypeString != "" {
			tags = append(tags, target.BaseTypeString)
			break
		}

		visited[typeToQuery] = struct{}{}
		typeToQuery = target.BaseTypeAddr
		if isZeroTypeKey(typeToQuery) {
			tags = append(tags, "void")
			break
		}
	}

	return tags
}

func extractSourceLocation(fileLocation string) sourceLocation {
	parts := strings.Split(fileLocation, ":")
	sourceFile := ""
	sourceLine := "-1"
	if len(parts) > 0 {
		sourceFile = parts[0]
	}
	if len(parts) > 1 {
		sourceLine = parts[1]
	}
	return sourceLocation{
		SourceFile: sourceFile,
		SourceLine: sourceLine,
	}
}

func extractDebuggedFunctionSignature(function functionEntry, typeMap map[string]typeEntry) functionSignatureElems {
	var returnType any
	if len(function.TypeArguments) > 0 {
		returnType = extractFuncSigFriendlyTypeTags(function.TypeArguments[0], typeMap)
	} else {
		returnType = "N/A"
	}

	params := make([][]string, 0)
	if len(function.TypeArguments) > 1 {
		for _, argumentAddr := range function.TypeArguments[1:] {
			params = append(params, extractFuncSigFriendlyTypeTags(argumentAddr, typeMap))
		}
	}

	return functionSignatureElems{
		ReturnType: returnType,
		Params:     params,
	}
}

func convertParamListToStrV2(paramList []string) string {
	var pre strings.Builder
	var med strings.Builder
	var post strings.Builder

	for _, param := range paramList {
		switch param {
		case "DW_TAG_pointer_type":
			post.WriteByte('*')
		case "DW_TAG_reference_type":
			post.WriteByte('&')
		case "DW_TAG_structure_type":
			med.WriteString(" struct ")
		case "DW_TAG_base_type", "DW_TAG_typedef", "DW_TAG_class_type":
		case "DW_TAG_const_type":
			pre.WriteString("const ")
		case "DW_TAG_enumeration_type":
		default:
			med.WriteString(param)
		}
	}

	return strings.TrimSpace(fmt.Sprintf("%s %s %s", strings.TrimSpace(pre.String()), med.String(), post.String()))
}

func isStruct(paramList []string) bool {
	for _, param := range paramList {
		if param == "DW_TAG_structure_type" {
			return true
		}
	}
	return false
}

func isEnumeration(paramList []string) bool {
	for _, param := range paramList {
		if param == "DW_TAG_enumeration_type" {
			return true
		}
	}
	return false
}

func toJSONNumber(value string) any {
	if _, ok := normalizeSignedDecimal(value); ok {
		return json.Number(value)
	}
	return value
}

func buildStructMembersForScope(
	scopeAddr string,
	typeMap map[string]typeEntry,
	memberEntriesByScope map[string][]memberEntry,
	friendlyTypeCache map[string][]string,
) []map[string]any {
	structMembers := make([]map[string]any, 0)
	entries, ok := memberEntriesByScope[scopeAddr]
	if !ok {
		return structMembers
	}

	for _, entry := range entries {
		memberFriendlyType, cached := friendlyTypeCache[entry.BaseTypeAddr]
		if !cached {
			memberFriendlyType = extractFuncSigFriendlyTypeTags(entry.BaseTypeAddr, typeMap)
			friendlyTypeCache[entry.BaseTypeAddr] = memberFriendlyType
		}

		structMembers = append(structMembers, map[string]any{
			"addr":               toJSONNumber(entry.Addr),
			"elem_name":          entry.ElemName,
			"elem_friendly_type": convertParamListToStrV2(memberFriendlyType),
		})
	}

	return structMembers
}

func writeAllFriendlyDebugTypes(index typeIndex, outDir string) (string, *appError) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", newAppError("io_error", fmt.Sprintf("failed creating out_dir %s: %v", outDir, err))
	}

	outputPath := filepath.Join(outDir, "all-friendly-debug-types.json")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", newAppError("io_error", fmt.Sprintf("failed creating %s: %v", outputPath, err))
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)

	memberEntriesByScope := make(map[string][]memberEntry)
	for _, entry := range index.entries {
		if entry.Tag != "DW_TAG_member" {
			continue
		}

		memberEntriesByScope[entry.Scope] = append(memberEntriesByScope[entry.Scope], memberEntry{
			Addr:         entry.Addr,
			ElemName:     entry.Name,
			BaseTypeAddr: entry.BaseTypeAddr,
		})
	}

	friendlyTypeCache := make(map[string][]string)
	structMembersCache := make(map[string][]map[string]any)

	if _, err := writer.WriteString("{"); err != nil {
		return "", newAppError("io_error", fmt.Sprintf("failed writing output JSON header: %v", err))
	}

	writtenEntries := 0
	for _, addr := range index.addrOrder {
		debugEntry, ok := index.entries[addr]
		if !ok {
			continue
		}

		friendlyType, cached := friendlyTypeCache[addr]
		if !cached {
			friendlyType = extractFuncSigFriendlyTypeTags(addr, index.entries)
			friendlyTypeCache[addr] = friendlyType
		}

		isStructType := isStruct(friendlyType)
		structureElems := make([]map[string]any, 0)
		if isStructType {
			cachedStructMembers, cached := structMembersCache[addr]
			if cached {
				structureElems = cachedStructMembers
			} else {
				structureElems = buildStructMembersForScope(
					addr, index.entries, memberEntriesByScope, friendlyTypeCache,
				)
				structMembersCache[addr] = structureElems
			}
		}

		entry := map[string]any{
			"raw_debug_info": debugEntry.RawDebugInfo,
			"friendly-info": map[string]any{
				"raw-types":    friendlyType,
				"string_type":  convertParamListToStrV2(friendlyType),
				"is-struct":    isStructType,
				"struct-elems": structureElems,
				"is-enum":      isEnumeration(friendlyType),
				"enum-elems":   debugEntry.EnumElems,
			},
		}

		if writtenEntries > 0 {
			if _, err := writer.WriteString(","); err != nil {
				return "", newAppError("io_error", fmt.Sprintf("failed writing output JSON separator: %v", err))
			}
		}

		keyBytes, err := json.Marshal(addr)
		if err != nil {
			return "", newAppError("io_error", fmt.Sprintf("failed serializing friendly type key for %s: %v", addr, err))
		}
		if _, err := writer.Write(keyBytes); err != nil {
			return "", newAppError("io_error", fmt.Sprintf("failed writing output JSON key: %v", err))
		}
		if _, err := writer.WriteString(":"); err != nil {
			return "", newAppError("io_error", fmt.Sprintf("failed writing output JSON colon: %v", err))
		}

		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return "", newAppError("io_error", fmt.Sprintf("failed serializing friendly type entry for %s: %v", addr, err))
		}
		if _, err := writer.Write(entryBytes); err != nil {
			return "", newAppError("io_error", fmt.Sprintf("failed writing output JSON entry: %v", err))
		}

		writtenEntries++
	}

	if _, err := writer.WriteString("}"); err != nil {
		return "", newAppError("io_error", fmt.Sprintf("failed writing output JSON trailer: %v", err))
	}
	if err := writer.Flush(); err != nil {
		return "", newAppError("io_error", fmt.Sprintf("failed flushing %s: %v", outputPath, err))
	}

	return outputPath, nil
}

func correlateFunction(function functionEntry, typeMap map[string]typeEntry) correlatedRecord {
	return correlatedRecord{
		RowIdx:             function.OriginalRowIdx,
		FuncSignatureElems: extractDebuggedFunctionSignature(function, typeMap),
		Source:             extractSourceLocation(function.FileLocation),
	}
}

func correlateChunkParallel(functionChunk []functionEntry, typeMap map[string]typeEntry) []correlatedRecord {
	if len(functionChunk) == 0 {
		return []correlatedRecord{}
	}

	workerCount := minInt(availableWorkerCount(), len(functionChunk))
	if workerCount <= 1 {
		records := make([]correlatedRecord, 0, len(functionChunk))
		for _, function := range functionChunk {
			records = append(records, correlateFunction(function, typeMap))
		}
		return records
	}

	results := make(chan indexedCorrelatedRecord, len(functionChunk))
	var workers sync.WaitGroup
	for workerIdx := 0; workerIdx < workerCount; workerIdx++ {
		workers.Add(1)
		go func(workerStart int) {
			defer workers.Done()
			for chunkOffset := workerStart; chunkOffset < len(functionChunk); chunkOffset += workerCount {
				results <- indexedCorrelatedRecord{
					chunkOffset: chunkOffset,
					record:      correlateFunction(functionChunk[chunkOffset], typeMap),
				}
			}
		}(workerIdx)
	}

	go func() {
		workers.Wait()
		close(results)
	}()

	indexedRecords := make([]indexedCorrelatedRecord, 0, len(functionChunk))
	for result := range results {
		indexedRecords = append(indexedRecords, result)
	}
	if len(indexedRecords) != len(functionChunk) {
		records := make([]correlatedRecord, 0, len(functionChunk))
		for _, function := range functionChunk {
			records = append(records, correlateFunction(function, typeMap))
		}
		return records
	}

	sort.Slice(indexedRecords, func(left int, right int) bool {
		return indexedRecords[left].chunkOffset < indexedRecords[right].chunkOffset
	})

	records := make([]correlatedRecord, 0, len(functionChunk))
	for _, indexedRecord := range indexedRecords {
		records = append(records, indexedRecord.record)
	}
	return records
}

func correlateChunkWithCache(functionChunk []functionEntry, typeMap map[string]typeEntry) []correlatedRecord {
	if len(functionChunk) == 0 {
		return []correlatedRecord{}
	}

	uniqueFunctions, rowToUniqueIdx := buildCorrelationPlan(functionChunk)
	uniqueRecords := correlateChunkParallel(uniqueFunctions, typeMap)

	records := make([]correlatedRecord, 0, len(functionChunk))
	for chunkOffset, function := range functionChunk {
		cachedRecord := uniqueRecords[rowToUniqueIdx[chunkOffset]]
		records = append(records, correlatedRecord{
			RowIdx: function.OriginalRowIdx,
			FuncSignatureElems: functionSignatureElems{
				ReturnType: cachedRecord.FuncSignatureElems.ReturnType,
				Params:     cachedRecord.FuncSignatureElems.Params,
			},
			Source: sourceLocation{
				SourceFile: cachedRecord.Source.SourceFile,
				SourceLine: cachedRecord.Source.SourceLine,
			},
		})
	}
	return records
}

func correlateAndWriteShards(
	functions []functionEntry,
	typeMap map[string]typeEntry,
	outputDir string,
	shardSize int,
) (correlationWriteResult, *appError) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return correlationWriteResult{}, newAppError("io_error", fmt.Sprintf("failed creating output_dir %s: %v", outputDir, err))
	}

	result := correlationWriteResult{
		CorrelatedShards: make([]string, 0),
	}

	if shardSize < 1 {
		shardSize = 1
	}

	shardIdx := 0
	for start := 0; start < len(functions); start += shardSize {
		end := minInt(start+shardSize, len(functions))
		functionChunk := functions[start:end]
		if len(functionChunk) == 0 {
			continue
		}

		correlateStarted := time.Now()
		correlatedChunk := correlateChunkWithCache(functionChunk, typeMap)
		result.CorrelateMS += toMS(time.Since(correlateStarted))

		shardPath := filepath.Join(outputDir, fmt.Sprintf("correlated-debug-%05d.ndjson", shardIdx))
		shardFile, err := os.Create(shardPath)
		if err != nil {
			return correlationWriteResult{}, newAppError("io_error", fmt.Sprintf("failed creating shard %s: %v", shardPath, err))
		}

		writeStarted := time.Now()
		writer := bufio.NewWriter(shardFile)
		for _, record := range correlatedChunk {
			recordBytes, err := json.Marshal(record)
			if err != nil {
				shardFile.Close()
				return correlationWriteResult{}, newAppError("io_error", fmt.Sprintf("failed serializing shard record %s: %v", shardPath, err))
			}
			if _, err := writer.Write(recordBytes); err != nil {
				shardFile.Close()
				return correlationWriteResult{}, newAppError("io_error", fmt.Sprintf("failed writing shard line %s: %v", shardPath, err))
			}
			if err := writer.WriteByte('\n'); err != nil {
				shardFile.Close()
				return correlationWriteResult{}, newAppError("io_error", fmt.Sprintf("failed writing shard newline %s: %v", shardPath, err))
			}
			result.WrittenRecords++
		}

		if err := writer.Flush(); err != nil {
			shardFile.Close()
			return correlationWriteResult{}, newAppError("io_error", fmt.Sprintf("failed flushing shard %s: %v", shardPath, err))
		}
		if err := shardFile.Close(); err != nil {
			return correlationWriteResult{}, newAppError("io_error", fmt.Sprintf("failed closing shard %s: %v", shardPath, err))
		}

		result.WriteMS += toMS(time.Since(writeStarted))
		result.CorrelatedShards = append(result.CorrelatedShards, shardPath)
		shardIdx++
	}

	return result, nil
}

func resolveOutputDir(input request) (string, *appError) {
	if input.OutputDir != nil {
		outputDir := strings.TrimSpace(*input.OutputDir)
		if outputDir != "" {
			return outputDir, nil
		}
	}
	if input.OutDir != nil {
		outDir := strings.TrimSpace(*input.OutDir)
		if outDir != "" {
			return outDir, nil
		}
	}
	return "", newAppError("invalid_request", "missing required output_dir (or compatibility out_dir)")
}

func buildOKResponse(
	schemaVersion int64,
	outputCounters counters,
	outputArtifacts artifacts,
	outputTimings timings,
) response {
	if outputArtifacts.CorrelatedShards == nil {
		outputArtifacts.CorrelatedShards = []string{}
	}

	return response{
		SchemaVersion: schemaVersion,
		Status:        "success",
		Counters:      outputCounters,
		Artifacts:     outputArtifacts,
		Timings:       outputTimings,
	}
}

func buildErrorResponse(schemaVersion int64, reasonCode string, outputTimings timings) response {
	reason := reasonCode
	return response{
		SchemaVersion: schemaVersion,
		Status:        "error",
		Counters:      counters{},
		Artifacts: artifacts{
			CorrelatedShards: []string{},
		},
		Timings:    outputTimings,
		ReasonCode: &reason,
	}
}

func runRequest(input request) (response, *appError) {
	totalStarted := time.Now()
	outputTimings := timings{}
	outputCounters := counters{}
	outputArtifacts := artifacts{
		CorrelatedShards: []string{},
	}

	shardSize := defaultShardSize
	if input.ShardSize != nil {
		shardSize = *input.ShardSize
	}
	if shardSize < 1 {
		shardSize = 1
	}

	outputDir, err := resolveOutputDir(input)
	if err != nil {
		return response{}, err
	}

	parseStarted := time.Now()
	var rawTypeRecords []any
	if len(input.DebugTypesPaths) == 0 {
		rawTypeRecords = append([]any(nil), input.DebugTypes...)
	} else {
		loadedRecords, loadErr := loadRecordsFromPaths(input.DebugTypesPaths)
		if loadErr != nil {
			return response{}, loadErr
		}
		rawTypeRecords = loadedRecords
	}

	var rawFunctionRecords []any
	if len(input.DebugFunctionsPaths) == 0 {
		rawFunctionRecords = append([]any(nil), input.DebugFunctions...)
	} else {
		loadedRecords, loadErr := loadRecordsFromPaths(input.DebugFunctionsPaths)
		if loadErr != nil {
			return response{}, loadErr
		}
		rawFunctionRecords = loadedRecords
	}

	outputCounters.ParsedTypes = len(rawTypeRecords)
	outputCounters.ParsedFunctions = len(rawFunctionRecords)

	typeIndex := buildTypeIndex(rawTypeRecords)
	parsedFunctions := make([]functionEntry, 0, len(rawFunctionRecords))
	for rowIdx, rawRecord := range rawFunctionRecords {
		entry := parseFunctionEntry(rawRecord, rowIdx)
		if entry != nil {
			parsedFunctions = append(parsedFunctions, *entry)
		}
	}
	outputTimings.ParseMS = toMS(time.Since(parseStarted))

	dedupeStarted := time.Now()
	memoizedInputs, _ := buildCorrelationPlan(parsedFunctions)
	outputCounters.DedupedFunctions = len(memoizedInputs)
	outputTimings.DedupeMS = toMS(time.Since(dedupeStarted))

	dumpFiles := true
	if input.DumpFiles != nil {
		dumpFiles = *input.DumpFiles
	}

	if dumpFiles {
		friendlyOutputDir := outputDir
		if input.OutDir != nil {
			outDir := strings.TrimSpace(*input.OutDir)
			if outDir != "" {
				friendlyOutputDir = outDir
			}
		}

		writeStarted := time.Now()
		outputPath, writeErr := writeAllFriendlyDebugTypes(typeIndex, friendlyOutputDir)
		if writeErr != nil {
			return response{}, writeErr
		}
		outputArtifacts.AllFriendlyDebugTypes = &outputPath
		outputTimings.WriteMS += toMS(time.Since(writeStarted))
	}

	correlationResult, correlationErr := correlateAndWriteShards(
		parsedFunctions, typeIndex.entries, outputDir, shardSize,
	)
	if correlationErr != nil {
		return response{}, correlationErr
	}

	outputCounters.WrittenRecords = correlationResult.WrittenRecords
	outputCounters.UpdatedFunctions = correlationResult.WrittenRecords
	outputCounters.CorrelatedFunctions = correlationResult.WrittenRecords
	outputCounters.Shards = len(correlationResult.CorrelatedShards)
	outputArtifacts.CorrelatedShards = correlationResult.CorrelatedShards

	outputTimings.CorrelateMS += correlationResult.CorrelateMS
	outputTimings.WriteMS += correlationResult.WriteMS
	outputTimings.TotalMS = toMS(time.Since(totalStarted))

	return buildOKResponse(input.SchemaVersion, outputCounters, outputArtifacts, outputTimings), nil
}

func emitResponse(output response) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(output)
}

func main() {
	started := time.Now()

	rawPayload, err := io.ReadAll(os.Stdin)
	if err != nil {
		outputTimings := timings{
			TotalMS: toMS(time.Since(started)),
		}
		emitResponse(buildErrorResponse(0, "io_error", outputTimings))
		fmt.Fprintf(os.Stderr, "failed reading stdin: %v\n", err)
		return
	}

	schemaVersion := extractSchemaVersion(rawPayload)
	input, err := parseRequest(rawPayload)
	if err != nil {
		outputTimings := timings{
			TotalMS: toMS(time.Since(started)),
		}
		emitResponse(buildErrorResponse(schemaVersion, "invalid_request", outputTimings))
		fmt.Fprintf(os.Stderr, "invalid request payload: %v\n", err)
		return
	}

	runResponse, runErr := runRequest(input)
	if runErr != nil {
		outputTimings := timings{
			TotalMS: toMS(time.Since(started)),
		}
		emitResponse(buildErrorResponse(schemaVersion, runErr.reasonCode, outputTimings))
		fmt.Fprintf(os.Stderr, "%s: %s\n", runErr.reasonCode, runErr.message)
		return
	}

	emitResponse(runResponse)
}
