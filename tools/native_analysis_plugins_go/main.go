package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const schemaVersion int64 = 1

type request struct {
	SchemaVersion int64           `json:"schema_version"`
	Plugins       []string        `json:"plugins"`
	ProjectData   json.RawMessage `json:"project_data"`
}

type response struct {
	SchemaVersion int64                   `json:"schema_version"`
	Status        string                  `json:"status"`
	Results       map[string]pluginResult `json:"results"`
	ReasonCode    string                  `json:"reason_code,omitempty"`
	ElapsedMS     uint64                  `json:"elapsed_ms"`
}

type pluginResult struct {
	Tables  map[string][]any `json:"tables"`
	Summary string           `json:"summary"`
}

type parsedProjectData struct {
	Functions  []functionEntry `json:"functions"`
	TargetLang string          `json:"target_lang"`
}

type functionEntry struct {
	Name                      string   `json:"name"`
	Hitcount                  uint64   `json:"hitcount"`
	ArgCount                  uint64   `json:"arg_count"`
	CyclomaticComplexity      int64    `json:"cyclomatic_complexity"`
	TotalCyclomaticComplexity int64    `json:"total_cyclomatic_complexity"`
	NewUnreachedComplexity    int64    `json:"new_unreached_complexity"`
	BBCount                   uint64   `json:"bb_count"`
	FunctionsReached          []string `json:"functions_reached"`
	FunctionsReachedCount     uint64   `json:"functions_reached_count"`
	ReachedByFuzzers          []string `json:"reached_by_fuzzers"`
	RuntimeCoveragePercent    float64  `json:"runtime_coverage_percent"`
	IsAccessible              *bool    `json:"is_accessible"`
	IsJVMLibrary              bool     `json:"is_jvm_library"`
	IsEnum                    bool     `json:"is_enum"`
	SourceFile                string   `json:"source_file"`
	IncomingReferences        []string `json:"incoming_references"`
}

type sinkDataset map[string]sinkDefinition

type sinkDefinition struct {
	Sink map[string][][]string `json:"sink"`
}

type sinkTarget struct {
	CWE     string
	Package string
	Func    string
}

//go:embed sinks_data.json
var sinksDataRaw []byte

var (
	sinkTargetsByLang map[string][]sinkTarget
	sinkTargetsErr    error
	sinkTargetsOnce   sync.Once
)

func effectiveReachedCount(function functionEntry) uint64 {
	if function.FunctionsReachedCount > 0 || len(function.FunctionsReached) == 0 {
		return function.FunctionsReachedCount
	}
	return uint64(len(function.FunctionsReached))
}

func isAccessible(function functionEntry) bool {
	if function.IsAccessible == nil {
		return true
	}
	return *function.IsAccessible
}

func qualifiesAsOptimalTarget(function functionEntry) bool {
	if function.Hitcount != 0 || effectiveReachedCount(function) < 1 || function.ArgCount == 0 {
		return false
	}
	if function.Name == "main" || strings.Contains(function.Name, "main2") {
		return false
	}
	if function.TotalCyclomaticComplexity < 20 || function.BBCount <= 1 {
		return false
	}
	return function.NewUnreachedComplexity >= 35
}

func runOptimalTargets(parsedData parsedProjectData) pluginResult {
	type candidate struct {
		Index    int
		Function functionEntry
	}
	candidates := make([]candidate, 0)
	for index, function := range parsedData.Functions {
		if qualifiesAsOptimalTarget(function) {
			candidates = append(candidates, candidate{Index: index, Function: function})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Function.NewUnreachedComplexity > candidates[j].Function.NewUnreachedComplexity
	})
	if len(candidates) > 200 {
		candidates = candidates[:200]
	}
	rows := make([]any, 0, len(candidates))
	for _, candidate := range candidates {
		function := candidate.Function
		rows = append(rows, map[string]any{
			"function_name":               function.Name,
			"cyclomatic_complexity":       function.CyclomaticComplexity,
			"total_cyclomatic_complexity": function.TotalCyclomaticComplexity,
			"new_unreached_complexity":    function.NewUnreachedComplexity,
			"functions_reached_count":     effectiveReachedCount(function),
			"arg_count":                   function.ArgCount,
			"bb_count":                    function.BBCount,
			"source_file":                 function.SourceFile,
		})
	}
	return pluginResult{
		Tables:  map[string][]any{"optimal_targets": rows},
		Summary: fmt.Sprintf("optimal_targets: %d candidate(s) found out of %d total functions", len(rows), len(parsedData.Functions)),
	}
}

func runRuntimeCoverageAnalysis(parsedData parsedProjectData) pluginResult {
	type candidate struct {
		Function functionEntry
	}
	candidates := make([]candidate, 0)
	for _, function := range parsedData.Functions {
		if function.Hitcount > 0 && function.NewUnreachedComplexity > 20 {
			candidates = append(candidates, candidate{Function: function})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Function.NewUnreachedComplexity > candidates[j].Function.NewUnreachedComplexity
	})
	if len(candidates) > 200 {
		candidates = candidates[:200]
	}
	rows := make([]any, 0, len(candidates))
	for _, candidate := range candidates {
		function := candidate.Function
		rows = append(rows, map[string]any{
			"function_name":               function.Name,
			"hitcount":                    function.Hitcount,
			"new_unreached_complexity":    function.NewUnreachedComplexity,
			"total_cyclomatic_complexity": function.TotalCyclomaticComplexity,
			"reached_by_fuzzers":          function.ReachedByFuzzers,
		})
	}
	return pluginResult{
		Tables:  map[string][]any{"runtime_coverage": rows},
		Summary: fmt.Sprintf("runtime_coverage_analysis: %d function(s) reached but with unreached sub-complexity", len(rows)),
	}
}

func runCalltreeAnalysis(parsedData parsedProjectData) pluginResult {
	total := len(parsedData.Functions)
	reached := 0
	for _, function := range parsedData.Functions {
		if function.Hitcount > 0 {
			reached++
		}
	}
	reachPercentage := 0.0
	if total > 0 {
		reachPercentage = (float64(reached) / float64(total)) * 100.0
	}
	reachPercentage = float64(int(reachPercentage*10+0.5)) / 10.0
	row := map[string]any{
		"total_functions":     total,
		"reached_functions":   reached,
		"unreached_functions": total - reached,
		"reach_percentage":    reachPercentage,
		"target_lang":         fallbackTargetLang(parsedData.TargetLang),
	}
	return pluginResult{
		Tables:  map[string][]any{"calltree_nodes": {row}},
		Summary: fmt.Sprintf("calltree_analysis: %d/%d functions reached (%.1f%%) for lang=%s", reached, total, reachPercentage, fallbackTargetLang(parsedData.TargetLang)),
	}
}

func runFunctionTable(parsedData parsedProjectData) pluginResult {
	type candidate struct {
		Index    int
		Function functionEntry
	}
	sortedFunctions := make([]candidate, 0, len(parsedData.Functions))
	for index, function := range parsedData.Functions {
		sortedFunctions = append(sortedFunctions, candidate{Index: index, Function: function})
	}
	sort.SliceStable(sortedFunctions, func(i, j int) bool {
		return sortedFunctions[i].Function.TotalCyclomaticComplexity > sortedFunctions[j].Function.TotalCyclomaticComplexity
	})
	orderedNames := make([]any, 0, len(sortedFunctions))
	topComplexity := int64(0)
	for index, candidate := range sortedFunctions {
		if index == 0 {
			topComplexity = candidate.Function.TotalCyclomaticComplexity
		}
		orderedNames = append(orderedNames, candidate.Function.Name)
	}
	return pluginResult{
		Tables:  map[string][]any{"ordered_function_names": orderedNames},
		Summary: fmt.Sprintf("function_table: %d function(s), top total_cyclomatic_complexity=%d", len(sortedFunctions), topComplexity),
	}
}

func runFarReachLowCoverageAnalysis(parsedData parsedProjectData) pluginResult {
	type candidate struct {
		Index    int
		Function functionEntry
	}
	candidates := make([]candidate, 0)
	for index, function := range parsedData.Functions {
		if !isAccessible(function) || function.IsJVMLibrary || function.IsEnum || function.RuntimeCoveragePercent > 20.0 {
			continue
		}
		candidates = append(candidates, candidate{Index: index, Function: function})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidates[i].Function
		right := candidates[j].Function
		if left.CyclomaticComplexity != right.CyclomaticComplexity {
			return left.CyclomaticComplexity > right.CyclomaticComplexity
		}
		if left.RuntimeCoveragePercent != right.RuntimeCoveragePercent {
			return left.RuntimeCoveragePercent < right.RuntimeCoveragePercent
		}
		return candidates[i].Index < candidates[j].Index
	})
	rows := make([]any, 0, len(candidates))
	for _, candidate := range candidates {
		rows = append(rows, map[string]any{"function_name": candidate.Function.Name})
	}
	return pluginResult{
		Tables:  map[string][]any{"far_reach_candidates": rows},
		Summary: fmt.Sprintf("far_reach_low_coverage_analysis: %d candidate(s)", len(rows)),
	}
}

func fallbackTargetLang(targetLang string) string {
	if targetLang == "" {
		return "unknown"
	}
	return targetLang
}

func loadSinkTargets() (map[string][]sinkTarget, error) {
	sinkTargetsOnce.Do(func() {
		var dataset sinkDataset
		if err := json.Unmarshal(sinksDataRaw, &dataset); err != nil {
			sinkTargetsErr = err
			return
		}
		sinkTargetsByLang = map[string][]sinkTarget{}
		for cwe, definition := range dataset {
			for lang, rawTargets := range definition.Sink {
				for _, rawTarget := range rawTargets {
					if len(rawTarget) != 2 {
						continue
					}
					sinkTargetsByLang[lang] = append(sinkTargetsByLang[lang], sinkTarget{
						CWE:     cwe,
						Package: rawTarget[0],
						Func:    rawTarget[1],
					})
				}
			}
		}
	})
	return sinkTargetsByLang, sinkTargetsErr
}

func matchesSink(function functionEntry, target sinkTarget, lang string) bool {
	if lang == "" {
		lang = "c-cpp"
	}
	switch lang {
	case "c-cpp":
		bareName := function.Name
		if pos := strings.LastIndex(bareName, "::"); pos >= 0 {
			bareName = bareName[pos+2:]
		}
		return target.Package == "" && bareName == target.Func
	case "python":
		if strings.HasPrefix(function.Name, "<builtin>.") {
			return target.Package == "<builtin>" && strings.TrimPrefix(function.Name, "<builtin>.") == target.Func
		}
		return target.Package == function.SourceFile && function.Name == target.Func
	case "jvm":
		name := strings.TrimPrefix(function.Name, "[")
		if pos := strings.Index(name, "]"); pos >= 0 {
			name = name[:pos]
		}
		if pos := strings.Index(name, "("); pos >= 0 {
			name = name[:pos]
		}
		pos := strings.LastIndex(name, ".")
		if pos < 0 {
			return false
		}
		return target.Package == name[:pos] && target.Func == name[pos+1:]
	default:
		return false
	}
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := map[string]bool{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			unique = append(unique, value)
		}
	}
	sort.Strings(unique)
	return unique
}

func runSinkCoverageAnalysis(parsedData parsedProjectData) pluginResult {
	targetsByLang, err := loadSinkTargets()
	if err != nil {
		return pluginResult{Tables: map[string][]any{}, Summary: "sink_coverage_analysis: 0 sink(s) found across 0 CWE(s)"}
	}
	targetLang := parsedData.TargetLang
	if targetLang == "" {
		targetLang = "c-cpp"
	}
	targets := targetsByLang[targetLang]
	functionByName := make(map[string]functionEntry, len(parsedData.Functions))
	for _, function := range parsedData.Functions {
		functionByName[function.Name] = function
	}
	rows := make([]any, 0)
	seenCWEs := map[string]bool{}
	for _, function := range parsedData.Functions {
		for _, target := range targets {
			if !matchesSink(function, target, targetLang) {
				continue
			}
			callers := uniqueSortedStrings(function.IncomingReferences)
			fuzzerCallers := make([]string, 0)
			for _, caller := range callers {
				callerFunction, ok := functionByName[caller]
				if ok && len(callerFunction.ReachedByFuzzers) > 0 {
					fuzzerCallers = append(fuzzerCallers, caller)
				}
			}
			fuzzerCallers = uniqueSortedStrings(fuzzerCallers)
			rows = append(rows, map[string]any{
				"func_name":          function.Name,
				"cwe":                target.CWE,
				"source_file":        function.SourceFile,
				"reached_by_fuzzers": function.ReachedByFuzzers,
				"callers":            callers,
				"fuzzer_callers":     fuzzerCallers,
			})
			seenCWEs[target.CWE] = true
			break
		}
	}
	return pluginResult{
		Tables:  map[string][]any{"sink_coverage": rows},
		Summary: fmt.Sprintf("sink_coverage_analysis: %d sink(s) found across %d CWE(s)", len(rows), len(seenCWEs)),
	}
}

func parseProjectData(raw json.RawMessage) (parsedProjectData, error) {
	if len(raw) == 0 {
		return parsedProjectData{}, nil
	}
	var parsed parsedProjectData
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return parsedProjectData{}, err
	}
	return parsed, nil
}

func dispatchPlugin(name string, parsedData parsedProjectData) (pluginResult, bool) {
	switch name {
	case "optimal_targets":
		return runOptimalTargets(parsedData), true
	case "runtime_coverage_analysis":
		return runRuntimeCoverageAnalysis(parsedData), true
	case "calltree_analysis":
		return runCalltreeAnalysis(parsedData), true
	case "sink_coverage_analysis":
		return runSinkCoverageAnalysis(parsedData), true
	case "function_table":
		return runFunctionTable(parsedData), true
	case "far_reach_low_coverage_analysis":
		return runFarReachLowCoverageAnalysis(parsedData), true
	default:
		return pluginResult{}, false
	}
}

func runRequest(req request) (map[string]pluginResult, error) {
	parsedData, err := parseProjectData(req.ProjectData)
	if err != nil {
		return nil, err
	}
	results := make(map[string]pluginResult)
	for _, pluginName := range req.Plugins {
		if result, ok := dispatchPlugin(pluginName, parsedData); ok {
			results[pluginName] = result
		}
	}
	return results, nil
}

func emitResponse(resp response, exitCode int) {
	_ = json.NewEncoder(os.Stdout).Encode(resp)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func main() {
	started := time.Now()
	rawPayload, err := io.ReadAll(os.Stdin)
	if err != nil {
		emitResponse(response{SchemaVersion: 0, Status: "error", Results: map[string]pluginResult{}, ReasonCode: "io_error", ElapsedMS: uint64(time.Since(started).Milliseconds())}, 1)
	}
	var req request
	if err := json.Unmarshal(rawPayload, &req); err != nil {
		var schemaProbe map[string]any
		schemaVersionValue := int64(0)
		if json.Unmarshal(rawPayload, &schemaProbe) == nil {
			if rawSchemaVersion, ok := schemaProbe["schema_version"].(float64); ok {
				schemaVersionValue = int64(rawSchemaVersion)
			}
		}
		emitResponse(response{SchemaVersion: schemaVersionValue, Status: "error", Results: map[string]pluginResult{}, ReasonCode: "invalid_request", ElapsedMS: uint64(time.Since(started).Milliseconds())}, 1)
	}
	results, err := runRequest(req)
	if err != nil {
		emitResponse(response{SchemaVersion: req.SchemaVersion, Status: "error", Results: map[string]pluginResult{}, ReasonCode: "invalid_request", ElapsedMS: uint64(time.Since(started).Milliseconds())}, 1)
	}
	emitResponse(response{SchemaVersion: req.SchemaVersion, Status: "success", Results: results, ElapsedMS: uint64(time.Since(started).Milliseconds())}, 0)
}
