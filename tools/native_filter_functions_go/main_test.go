package main

import "testing"

func TestFilterProfileExcludesMatchingFunctionsAndConstructors(t *testing.T) {
	filePatterns, err := compilePatterns([]string{"generated/"}, "file")
	if err != nil {
		t.Fatalf("compilePatterns() error = %v", err)
	}
	funcPatterns, err := compilePatterns([]string{"skip_me"}, "function")
	if err != nil {
		t.Fatalf("compilePatterns() error = %v", err)
	}

	result := filterProfile(filePatterns, funcPatterns, profileInput{
		ProfileID:        "profile-a",
		FuzzerSourceFile: "fuzz_target.cc",
		AllClassFunctions: []functionEntry{
			{Key: "keep", FunctionSourceFile: "src/keep.cc", FunctionName: "keep", RawFunctionName: "keep"},
			{Key: "drop-by-file", FunctionSourceFile: "generated/file.cc", FunctionName: "keep", RawFunctionName: "keep"},
			{Key: "drop-by-name", FunctionSourceFile: "src/keep.cc", FunctionName: "skip_me", RawFunctionName: "skip_me"},
		},
		AllClassConstructors: []functionEntry{
			{Key: "ctor", FunctionSourceFile: "generated/ctor.cc", FunctionName: "Ctor", RawFunctionName: "Ctor"},
		},
	})

	if result.Excluded {
		t.Fatalf("filterProfile() unexpectedly excluded the profile")
	}
	if len(result.ExcludedFunctions) != 2 {
		t.Fatalf("filterProfile() excluded %d functions, want 2", len(result.ExcludedFunctions))
	}
	if result.ExcludedFunctions[0] != "drop-by-file" || result.ExcludedFunctions[1] != "drop-by-name" {
		t.Fatalf("filterProfile() excluded functions = %v", result.ExcludedFunctions)
	}
	if len(result.ExcludedConstructors) != 1 || result.ExcludedConstructors[0] != "ctor" {
		t.Fatalf("filterProfile() excluded constructors = %v", result.ExcludedConstructors)
	}
}

func TestFilterProfileExcludesWholeProfileOnSourceMatch(t *testing.T) {
	filePatterns, err := compilePatterns([]string{"fuzzers/excluded"}, "file")
	if err != nil {
		t.Fatalf("compilePatterns() error = %v", err)
	}

	result := filterProfile(filePatterns, nil, profileInput{
		ProfileID:        "profile-b",
		FuzzerSourceFile: "fuzzers/excluded_target.cc",
	})

	if !result.Excluded {
		t.Fatalf("filterProfile() did not exclude the matching profile")
	}
}

func TestCompilePatternsRejectsInvalidRegex(t *testing.T) {
	if _, err := compilePatterns([]string{"("}, "function"); err == nil {
		t.Fatal("compilePatterns() succeeded for invalid regex")
	}
}
