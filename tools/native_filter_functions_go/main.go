package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
)

const schemaVersion = 1

type inputPayload struct {
	SchemaVersion           int            `json:"schema_version"`
	FileExcludePatterns     []string       `json:"file_exclude_patterns"`
	FunctionExcludePatterns []string       `json:"function_exclude_patterns"`
	Profiles                []profileInput `json:"profiles"`
}

type profileInput struct {
	ProfileID            string          `json:"profile_id"`
	FuzzerSourceFile     string          `json:"fuzzer_source_file"`
	AllClassFunctions    []functionEntry `json:"all_class_functions"`
	AllClassConstructors []functionEntry `json:"all_class_constructors"`
}

type functionEntry struct {
	Key                string `json:"key"`
	FunctionSourceFile string `json:"function_source_file"`
	FunctionName       string `json:"function_name"`
	RawFunctionName    string `json:"raw_function_name"`
}

type outputPayload struct {
	SchemaVersion int             `json:"schema_version"`
	Status        string          `json:"status"`
	Profiles      []profileOutput `json:"profiles,omitempty"`
	Reason        string          `json:"reason,omitempty"`
}

type profileOutput struct {
	ProfileID            string   `json:"profile_id"`
	Excluded             bool     `json:"excluded"`
	ExcludedFunctions    []string `json:"excluded_functions,omitempty"`
	ExcludedConstructors []string `json:"excluded_constructors,omitempty"`
}

func matchesAny(patterns []*regexp.Regexp, value string) bool {
	if value == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func shouldExcludeFunction(filePatterns []*regexp.Regexp, funcPatterns []*regexp.Regexp, entry functionEntry) bool {
	if matchesAny(filePatterns, entry.FunctionSourceFile) {
		return true
	}
	if matchesAny(funcPatterns, entry.FunctionName) {
		return true
	}
	return matchesAny(funcPatterns, entry.RawFunctionName)
}

func compilePatterns(patterns []string, patternKind string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid %s exclude pattern %q: %w", patternKind, pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

func filterProfile(filePatterns []*regexp.Regexp, funcPatterns []*regexp.Regexp, profile profileInput) profileOutput {
	if matchesAny(filePatterns, profile.FuzzerSourceFile) {
		return profileOutput{ProfileID: profile.ProfileID, Excluded: true}
	}

	result := profileOutput{
		ProfileID:            profile.ProfileID,
		ExcludedFunctions:    make([]string, 0),
		ExcludedConstructors: make([]string, 0),
	}
	for _, entry := range profile.AllClassFunctions {
		if shouldExcludeFunction(filePatterns, funcPatterns, entry) {
			result.ExcludedFunctions = append(result.ExcludedFunctions, entry.Key)
		}
	}
	for _, entry := range profile.AllClassConstructors {
		if shouldExcludeFunction(filePatterns, funcPatterns, entry) {
			result.ExcludedConstructors = append(result.ExcludedConstructors, entry.Key)
		}
	}
	return result
}

func writeJSON(payload outputPayload, exitCode int) {
	_ = json.NewEncoder(os.Stdout).Encode(payload)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func run() error {
	rawInput, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	var payload inputPayload
	if err := json.Unmarshal(rawInput, &payload); err != nil {
		return fmt.Errorf("json parse error: %w", err)
	}
	if payload.SchemaVersion != schemaVersion {
		return fmt.Errorf("unsupported schema_version: %d", payload.SchemaVersion)
	}

	filePatterns, err := compilePatterns(payload.FileExcludePatterns, "file")
	if err != nil {
		return err
	}
	funcPatterns, err := compilePatterns(payload.FunctionExcludePatterns, "function")
	if err != nil {
		return err
	}

	results := make([]profileOutput, len(payload.Profiles))
	var wg sync.WaitGroup
	for idx, profile := range payload.Profiles {
		wg.Add(1)
		go func(index int, current profileInput) {
			defer wg.Done()
			results[index] = filterProfile(filePatterns, funcPatterns, current)
		}(idx, profile)
	}
	wg.Wait()

	writeJSON(outputPayload{
		SchemaVersion: schemaVersion,
		Status:        "success",
		Profiles:      results,
	}, 0)
	return nil
}

func main() {
	if err := run(); err != nil {
		writeJSON(outputPayload{
			SchemaVersion: schemaVersion,
			Status:        "error",
			Reason:        err.Error(),
		}, 1)
	}
}
