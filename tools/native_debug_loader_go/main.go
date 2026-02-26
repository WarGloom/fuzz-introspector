package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	functionsSectionStart = "## Functions defined in module"
	functionsSectionEnd   = "## Global variables"
	typesSectionStart     = "## Types defined in module"
)

type cliArgs struct {
	baseDir    string
	debugFiles []string
}

type sourceLocation struct {
	SourceFile string `json:"source_file"`
	SourceLine string `json:"source_line"`
}

type fileEntry struct {
	SourceFile string `json:"source_file"`
	Language   string `json:"language"`
}

type functionEntry struct {
	Name   string          `json:"name"`
	Source *sourceLocation `json:"source,omitempty"`
	Args   []string        `json:"args,omitempty"`
}

type globalVariableEntry struct {
	Name   string         `json:"name"`
	Source sourceLocation `json:"source"`
}

type typeElementEntry struct {
	Name   string         `json:"name"`
	Source sourceLocation `json:"source"`
}

type typeEntry struct {
	Type     string             `json:"type"`
	Name     string             `json:"name"`
	Source   sourceLocation     `json:"source"`
	Elements []typeElementEntry `json:"elements,omitempty"`
}

type outputPayload struct {
	AllFilesInProject     []fileEntry           `json:"all_files_in_project"`
	AllFunctionsInProject []functionEntry       `json:"all_functions_in_project"`
	AllGlobalVariables    []globalVariableEntry `json:"all_global_variables"`
	AllTypes              []typeEntry           `json:"all_types"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	args, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}

	if args.baseDir != "" {
		info, statErr := os.Stat(args.baseDir)
		if statErr != nil {
			return fmt.Errorf("--base-dir %q is invalid: %w", args.baseDir, statErr)
		}
		if !info.IsDir() {
			return fmt.Errorf("--base-dir %q is not a directory", args.baseDir)
		}
	}

	for _, path := range args.debugFiles {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return fmt.Errorf("debug file %q is invalid: %w", path, statErr)
		}
		if info.IsDir() {
			return fmt.Errorf("debug file %q is a directory", path)
		}
	}

	report, loadErr := loadDebugReport(args.debugFiles)
	if loadErr != nil {
		return loadErr
	}

	encoded, encErr := json.Marshal(report)
	if encErr != nil {
		return fmt.Errorf("failed to encode output JSON: %w", encErr)
	}
	fmt.Println(string(encoded))
	return nil
}

func usage(program string) string {
	return fmt.Sprintf(
		"Usage: %s [--base-dir <path>] <debug_files...>\nExample: %s --base-dir /work a.debug b.debug",
		program,
		program,
	)
}

func parseArgs(argv []string) (*cliArgs, error) {
	if len(argv) == 0 {
		return nil, errors.New("no arguments provided")
	}
	out := &cliArgs{
		debugFiles: make([]string, 0, len(argv)),
	}
	for idx := 0; idx < len(argv); idx++ {
		arg := argv[idx]
		if arg == "--help" || arg == "-h" {
			fmt.Println(usage(filepath.Base(os.Args[0])))
			os.Exit(0)
		}
		if arg == "--base-dir" {
			if out.baseDir != "" {
				return nil, errors.New("--base-dir was provided more than once")
			}
			idx++
			if idx >= len(argv) {
				return nil, fmt.Errorf("missing value for --base-dir\n%s",
					usage(filepath.Base(os.Args[0])))
			}
			out.baseDir = argv[idx]
			continue
		}
		if strings.HasPrefix(arg, "--") {
			return nil, fmt.Errorf("unknown option %q\n%s", arg,
				usage(filepath.Base(os.Args[0])))
		}
		out.debugFiles = append(out.debugFiles, arg)
	}
	if len(out.debugFiles) == 0 {
		return nil, fmt.Errorf("no debug files provided\n%s",
			usage(filepath.Base(os.Args[0])))
	}
	return out, nil
}

func loadDebugReport(debugFiles []string) (*outputPayload, error) {
	allFiles := map[string]fileEntry{}
	allFunctions := map[string]functionEntry{}
	allGlobals := map[string]globalVariableEntry{}
	allTypes := map[string]typeEntry{}
	seenHashes := map[uint64]struct{}{}

	for _, debugFile := range debugFiles {
		contentBytes, readErr := os.ReadFile(debugFile)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read debug file %q: %w", debugFile, readErr)
		}
		contentHash := stableContentHash(contentBytes)
		if _, exists := seenHashes[contentHash]; exists {
			continue
		}
		seenHashes[contentHash] = struct{}{}
		content := string(contentBytes)

		extractCompileUnits(content, allFiles)
		extractFunctions(content, allFunctions, allFiles)
		extractGlobalVariables(content, allGlobals, allFiles)
		extractTypes(content, allTypes, allFiles)
	}

	return &outputPayload{
		AllFilesInProject:     sortedFileEntries(allFiles),
		AllFunctionsInProject: sortedFunctionEntries(allFunctions),
		AllGlobalVariables:    sortedGlobalEntries(allGlobals),
		AllTypes:              sortedTypeEntries(allTypes),
	}, nil
}

func stableContentHash(input []byte) uint64 {
	hasher := fnv.New64a()
	_, _ = hasher.Write(input)
	return hasher.Sum64()
}

func extractCompileUnits(content string, files map[string]fileEntry) {
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "Compile unit:") {
			continue
		}
		splitLine := strings.Split(line, " ")
		language := "N/A"
		if len(splitLine) > 2 {
			language = splitLine[2]
		}
		sourceFile := ""
		if len(splitLine) > 0 {
			sourceFile = splitLine[len(splitLine)-1]
		}
		if sourceFile == "" {
			continue
		}
		if strings.Contains(sourceFile, "//") {
			pieces := strings.Split(sourceFile, "//")
			if len(pieces) > 1 {
				sourceFile = "/" + strings.Join(pieces[1:], "//")
			}
		}
		files[sourceFile] = fileEntry{
			SourceFile: sourceFile,
			Language:   language,
		}
	}
}

func extractGlobalVariables(content string, globals map[string]globalVariableEntry, files map[string]fileEntry) {
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "Global variable: ") {
			continue
		}
		clean := strings.TrimPrefix(line, "Global variable: ")
		pieces := strings.Split(clean, " from ")
		varName := pieces[0]
		location := pieces[len(pieces)-1]
		sourceFile := strings.Split(location, ":")[0]
		sourceLine := "-1"
		if locationParts := strings.Split(location, ":"); len(locationParts) > 1 {
			sourceLine = locationParts[1]
		}
		key := sourceFile + sourceLine
		globals[key] = globalVariableEntry{
			Name: varName,
			Source: sourceLocation{
				SourceFile: sourceFile,
				SourceLine: sourceLine,
			},
		}
		if _, exists := files[sourceFile]; !exists {
			files[sourceFile] = fileEntry{
				SourceFile: sourceFile,
				Language:   "N/A",
			}
		}
	}
}

type pendingTypeStruct struct {
	Name     string
	Source   sourceLocation
	Elements []typeElementEntry
}

func extractTypes(content string, types map[string]typeEntry, files map[string]fileEntry) {
	current := (*pendingTypeStruct)(nil)
	readTypes := false

	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, typesSectionStart) {
			readTypes = true
		}
		if !readTypes {
			continue
		}

		if strings.Contains(line, "Type: Name:") {
			if current != nil {
				key := current.Source.SourceFile + current.Source.SourceLine
				types[key] = typeEntry{
					Type:     "struct",
					Name:     current.Name,
					Source:   current.Source,
					Elements: current.Elements,
				}
				current = nil
			}

			if strings.Contains(line, "DW_TAG_structure") {
				structName := between(line, "{", "}")
				location := firstField(strings.TrimSpace(lastPart(line, "from")))
				sourceFile := strings.Split(location, ":")[0]
				sourceLine := "-1"
				if parts := strings.Split(location, ":"); len(parts) > 1 {
					sourceLine = parts[1]
				}
				current = &pendingTypeStruct{
					Name: structName,
					Source: sourceLocation{
						SourceFile: sourceFile,
						SourceLine: sourceLine,
					},
					Elements: []typeElementEntry{},
				}
				if _, exists := files[sourceFile]; !exists {
					files[sourceFile] = fileEntry{SourceFile: sourceFile, Language: "N/A"}
				}
			}

			if strings.Contains(line, "DW_TAG_typedef") {
				name := between(line, "{", "}")
				location := firstField(lastPart(line, " from "))
				sourceFile := strings.Split(location, ":")[0]
				sourceLine := "-1"
				if parts := strings.Split(location, ":"); len(parts) > 1 {
					sourceLine = parts[1]
				}
				key := sourceFile + sourceLine
				types[key] = typeEntry{
					Type:   "typedef",
					Name:   name,
					Source: sourceLocation{SourceFile: sourceFile, SourceLine: sourceLine},
				}
				if _, exists := files[sourceFile]; !exists {
					files[sourceFile] = fileEntry{SourceFile: sourceFile, Language: "N/A"}
				}
			}
		}

		if strings.Contains(line, "- Elem ") && current != nil {
			// Match existing Python extraction behavior exactly, including
			// retaining a trailing '}' in names such as "{e1}" -> "e1}".
			elemName := firstField(strings.TrimSpace(lastPart(line, "{")))
			location := firstField(strings.TrimSpace(lastPart(line, "from")))
			sourceFile := strings.Split(location, ":")[0]
			sourceLine := "-1"
			if parts := strings.Split(location, ":"); len(parts) > 1 {
				sourceLine = parts[1]
			}
			current.Elements = append(current.Elements, typeElementEntry{
				Name: elemName,
				Source: sourceLocation{
					SourceFile: sourceFile,
					SourceLine: sourceLine,
				},
			})
			if _, exists := files[sourceFile]; !exists {
				files[sourceFile] = fileEntry{SourceFile: sourceFile, Language: "N/A"}
			}
		}
	}

	if current != nil {
		key := current.Source.SourceFile + current.Source.SourceLine
		types[key] = typeEntry{
			Type:     "struct",
			Name:     current.Name,
			Source:   current.Source,
			Elements: current.Elements,
		}
	}
}

type pendingFunction struct {
	Name       string
	Source     *sourceLocation
	NamedArgs  []string
	OperandArg []string
}

func extractFunctions(content string, functions map[string]functionEntry, files map[string]fileEntry) {
	start := strings.Index(content, functionsSectionStart)
	if start < 0 {
		return
	}
	start += len(functionsSectionStart)
	if start < len(content) && content[start] == '\n' {
		start++
	}
	end := strings.Index(content[start:], functionsSectionEnd)
	if end < 0 {
		end = len(content)
	} else {
		end += start
	}
	section := content[start:end]

	current := (*pendingFunction)(nil)
	finalize := func() {
		if current == nil || current.Source == nil {
			return
		}
		args := current.OperandArg
		if len(current.NamedArgs) > 0 {
			args = current.NamedArgs
		}
		entry := functionEntry{
			Name:   current.Name,
			Source: current.Source,
			Args:   nil,
		}
		if len(args) > 0 {
			entry.Args = args
		}
		key := current.Source.SourceFile + current.Source.SourceLine
		functions[key] = entry
	}

	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "Subprogram: ") {
			finalize()
			current = &pendingFunction{
				Name:       strings.TrimSpace(strings.TrimPrefix(line, "Subprogram: ")),
				NamedArgs:  []string{},
				OperandArg: []string{},
			}
			continue
		}
		if current == nil {
			continue
		}

		if current.Source == nil {
			if sourceFile, sourceLine, ok := maybeExtractSourceLocation(line); ok {
				current.Source = &sourceLocation{
					SourceFile: sourceFile,
					SourceLine: sourceLine,
				}
				if _, exists := files[sourceFile]; !exists {
					files[sourceFile] = fileEntry{SourceFile: sourceFile, Language: "N/A"}
				}
			}
		}

		if namedArg, ok := maybeExtractNamedArg(line); ok {
			current.NamedArgs = append(current.NamedArgs, namedArg)
			continue
		}
		if opType, ok := maybeExtractOperandType(line); ok {
			current.OperandArg = append(current.OperandArg, opType)
		}
	}
	finalize()
}

func maybeExtractSourceLocation(line string) (string, string, bool) {
	if !strings.Contains(line, " from ") || strings.Contains(line, " - Operand") ||
		strings.Contains(line, "Elem ") {
		return "", "", false
	}
	location := strings.TrimSpace(lastPart(line, " from "))
	parts := strings.SplitN(location, ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	sourceFile := strings.TrimSpace(parts[0])
	sourceLineTail := parts[1]
	digits := make([]rune, 0, len(sourceLineTail))
	for _, ch := range sourceLineTail {
		if ch >= '0' && ch <= '9' {
			digits = append(digits, ch)
		} else {
			break
		}
	}
	if len(digits) == 0 {
		return "", "", false
	}
	return sourceFile, string(digits), true
}

func maybeExtractNamedArg(line string) (string, bool) {
	startMarker := "Name: {"
	start := strings.Index(line, startMarker)
	if start < 0 {
		return "", false
	}
	start += len(startMarker)
	end := strings.Index(line[start:], "}")
	if end < 0 {
		return "", false
	}
	value := strings.TrimSpace(line[start : start+end])
	if value == "" {
		return "", false
	}
	return value, true
}

func maybeExtractOperandType(line string) (string, bool) {
	if !strings.Contains(line, " - Operand") {
		return "", false
	}
	normalized := strings.ReplaceAll(line, "Operand Type:", "")
	normalized = strings.ReplaceAll(normalized, "Type: ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	pointerCount := strings.Count(normalized, "DW_TAG_pointer_type")
	constCount := strings.Count(normalized, "DW_TAG_const_type")
	parts := strings.Split(normalized, ",")
	if len(parts) == 0 {
		return "", false
	}
	baseType := strings.TrimSpace(parts[len(parts)-1])
	result := ""
	if constCount > 0 {
		result += "const "
	}
	result += baseType
	if pointerCount > 0 {
		result += " " + strings.Repeat("*", pointerCount)
	}
	result = strings.TrimSpace(result)
	if result == "" {
		return "", false
	}
	return result, true
}

func sortedFileEntries(files map[string]fileEntry) []fileEntry {
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]fileEntry, 0, len(keys))
	for _, key := range keys {
		out = append(out, files[key])
	}
	return out
}

func sortedFunctionEntries(functions map[string]functionEntry) []functionEntry {
	keys := make([]string, 0, len(functions))
	for key := range functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]functionEntry, 0, len(keys))
	for _, key := range keys {
		out = append(out, functions[key])
	}
	return out
}

func sortedGlobalEntries(globals map[string]globalVariableEntry) []globalVariableEntry {
	keys := make([]string, 0, len(globals))
	for key := range globals {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]globalVariableEntry, 0, len(keys))
	for _, key := range keys {
		out = append(out, globals[key])
	}
	return out
}

func sortedTypeEntries(types map[string]typeEntry) []typeEntry {
	keys := make([]string, 0, len(types))
	for key := range types {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]typeEntry, 0, len(keys))
	for _, key := range keys {
		out = append(out, types[key])
	}
	return out
}

func between(input, startMarker, endMarker string) string {
	start := strings.Index(input, startMarker)
	if start < 0 {
		return ""
	}
	start += len(startMarker)
	rest := input[start:]
	end := strings.Index(rest, endMarker)
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func lastPart(input, separator string) string {
	if strings.Contains(input, separator) {
		parts := strings.Split(input, separator)
		return parts[len(parts)-1]
	}
	return input
}

func firstField(input string) string {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
