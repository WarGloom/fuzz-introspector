package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func executeRequest(t *testing.T, req request) ([]branchComplexity, []branchBlocker) {
	t.Helper()
	tempDir := t.TempDir()
	req.OutputDir = tempDir

	inputFile, err := os.CreateTemp(tempDir, "request-*.json")
	if err != nil {
		t.Fatalf("CreateTemp(input) failed: %v", err)
	}
	defer inputFile.Close()
	if err := json.NewEncoder(inputFile).Encode(req); err != nil {
		t.Fatalf("Encode(request) failed: %v", err)
	}
	if _, err := inputFile.Seek(0, 0); err != nil {
		t.Fatalf("Seek(input) failed: %v", err)
	}

	stdoutFile, err := os.CreateTemp(tempDir, "stdout-*.json")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) failed: %v", err)
	}
	defer stdoutFile.Close()

	originalStdin := os.Stdin
	originalStdout := os.Stdout
	os.Stdin = inputFile
	os.Stdout = stdoutFile
	defer func() {
		os.Stdin = originalStdin
		os.Stdout = originalStdout
	}()

	if err := run(); err != nil {
		t.Fatalf("run() failed: %v", err)
	}

	var complexities []branchComplexity
	complexityPath := filepath.Join(tempDir, "branch_complexities.json")
	complexityData, err := os.ReadFile(complexityPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", complexityPath, err)
	}
	if err := json.Unmarshal(complexityData, &complexities); err != nil {
		t.Fatalf("Unmarshal(branch_complexities) failed: %v", err)
	}

	var blockers []branchBlocker
	blockerPath := filepath.Join(tempDir, "branch_blockers.json")
	blockerData, err := os.ReadFile(blockerPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", blockerPath, err)
	}
	if err := json.Unmarshal(blockerData, &blockers); err != nil {
		t.Fatalf("Unmarshal(branch_blockers) failed: %v", err)
	}

	return complexities, blockers
}

func TestSplitBranchKeyUsesLastColonAndFirstComma(t *testing.T) {
	functionName, line, column, ok := splitBranchKey("pkg::Func:17,9")
	if !ok {
		t.Fatal("splitBranchKey() returned ok=false")
	}
	if functionName != "pkg::Func" || line != "17" || column != "9" {
		t.Fatalf("splitBranchKey() = (%q, %q, %q)", functionName, line, column)
	}
}

func TestParseSideLineRejectsMalformedInput(t *testing.T) {
	if _, ok := parseSideLine("missing"); ok {
		t.Fatal("parseSideLine() accepted malformed position")
	}
}

func TestColorForHitcountMatchesThresholds(t *testing.T) {
	cases := []struct {
		hitCount int
		want     string
	}{
		{0, "red"},
		{1, "gold"},
		{10, "yellow"},
		{30, "greenyellow"},
		{50, "lawngreen"},
	}
	for _, tc := range cases {
		if got := colorForHitcount(tc.hitCount); got != tc.want {
			t.Fatalf("colorForHitcount(%d) = %q, want %q", tc.hitCount, got, tc.want)
		}
	}
}

func TestIsSideHitPrefersFileCoverageAndFallsBackToFunctionCoverage(t *testing.T) {
	coverage := coverageData{
		FileMap: map[string][][]int{"src/file.c": {{10, 3}}},
		CovMap:  map[string][][]int{"func": {{20, 7}}},
	}
	if !isSideHit(coverage, "src/file.c", "func", 10) {
		t.Fatal("isSideHit() did not use file coverage")
	}
	if !isSideHit(coverage, "missing.c", "func", 20) {
		t.Fatal("isSideHit() did not fall back to function coverage")
	}
	if isSideHit(coverage, "missing.c", "func", 99) {
		t.Fatal("isSideHit() reported a missing line as hit")
	}
}

func TestBuildOverlayNodesUsesCoverageLookupNameForCppParity(t *testing.T) {
	req := request{
		TargetLang: "c-cpp",
		Callsites: []callsite{
			{
				CovCtIdx:           0,
				Depth:              0,
				DstFunctionName:    "_Z5entryv",
				CoverageLookupName: "entry()",
			},
			{
				CovCtIdx:           1,
				Depth:              1,
				DstFunctionName:    "_Z4leafv",
				CoverageLookupName: "leaf()",
				SrcLineNumber:      7,
			},
		},
		Coverage: coverageData{
			Type: "function",
			CovMap: map[string][][]int{
				"entry()": {{1, 5}, {7, 11}},
				"leaf()":  {{3, 1}},
			},
		},
	}

	nodes := buildOverlayNodes(req)
	if len(nodes) != 2 {
		t.Fatalf("buildOverlayNodes() produced %d nodes", len(nodes))
	}
	if nodes[0].CovHitcount != 200 {
		t.Fatalf("root hitcount = %d, want 200 sentinel", nodes[0].CovHitcount)
	}
	if nodes[1].CovHitcount != 11 {
		t.Fatalf("child hitcount = %d, want 11", nodes[1].CovHitcount)
	}
}

func TestKernelHitcountMatchesPythonKernelWindowSemantics(t *testing.T) {
	modules := []kernelModule{{
		Filename: "/build/out/src/foo.c",
		Covered:  []int{15},
	}}
	if got := kernelHitcount(modules, "../src/foo.c", 10); got != 100 {
		t.Fatalf("kernelHitcount() = %d, want 100", got)
	}
	if got := kernelHitcount(modules, "../src/foo.c", 16); got != 0 {
		t.Fatalf("kernelHitcount() = %d, want 0 outside window", got)
	}
}

func TestBuildOverlayNodesUsesKernelCoverageForCpp(t *testing.T) {
	req := request{
		TargetLang: "c-cpp",
		Callsites: []callsite{
			{
				CovCtIdx:              0,
				Depth:                 0,
				DstFunctionName:       "entry",
				CoverageLookupName:    "entry",
				DstFunctionSourceFile: "../src/foo.c",
			},
			{
				CovCtIdx:              1,
				Depth:                 1,
				DstFunctionName:       "child",
				CoverageLookupName:    "child",
				DstFunctionSourceFile: "../src/bar.c",
				SrcLineNumber:         10,
			},
		},
		Coverage: coverageData{
			Type: "kernel",
			KernelCoverage: []kernelModule{{
				Filename: "/tmp/build/src/foo.c",
				Covered:  []int{18},
			}},
		},
	}

	nodes := buildOverlayNodes(req)
	if len(nodes) != 2 {
		t.Fatalf("buildOverlayNodes() produced %d nodes", len(nodes))
	}
	if nodes[0].CovHitcount != 200 {
		t.Fatalf("root hitcount = %d, want 200 sentinel", nodes[0].CovHitcount)
	}
	if nodes[1].CovHitcount != 100 {
		t.Fatalf("child hitcount = %d, want 100 kernel hit", nodes[1].CovHitcount)
	}
}

func TestBuildOverlayNodesUsesPythonParentFileHitParity(t *testing.T) {
	req := request{
		TargetLang: "python",
		Callsites: []callsite{
			{
				CovCtIdx:           0,
				Depth:              0,
				DstFunctionName:    "pkg.entry",
				CoverageLookupName: "pkg.entry",
			},
			{
				CovCtIdx:            1,
				Depth:               1,
				DstFunctionName:     "pkg.leaf",
				CoverageLookupName:  "pkg.leaf",
				SrcLineNumber:       12,
				PythonParentFileHit: true,
			},
		},
		Coverage: coverageData{
			Type:   "file",
			CovMap: map[string][][]int{"pkg.entry": {{1, 5}}},
		},
	}

	nodes := buildOverlayNodes(req)
	if len(nodes) != 2 {
		t.Fatalf("buildOverlayNodes() produced %d nodes", len(nodes))
	}
	if nodes[0].CovHitcount != 200 {
		t.Fatalf("root hitcount = %d, want 200 sentinel", nodes[0].CovHitcount)
	}
	if nodes[1].CovHitcount != 200 {
		t.Fatalf("child hitcount = %d, want 200 python file-hit sentinel", nodes[1].CovHitcount)
	}
}

func TestBranchComplexityUsesFunctionCoverageLookupNameForCpp(t *testing.T) {
	req := request{
		TargetLang: "c-cpp",
		Functions: map[string]functionData{
			"_Z3foov": {
				FunctionSourceFile:        "a.cc",
				CoverageLookupName:        "foo()",
				TotalCyclomaticComplexity: 7,
				BranchProfiles: map[string]branch{
					"a.cc:10,1": {
						Sides: []branchSide{{Pos: "a.cc:11,1", Funcs: []string{"_Z3foov"}}},
					},
				},
			},
		},
		Coverage: coverageData{
			Type:   "function",
			CovMap: map[string][][]int{"foo()": {{11, 3}}},
		},
	}

	complexities, _ := executeRequest(t, req)
	if len(complexities) != 1 {
		t.Fatalf("got %d branch complexities, want 1", len(complexities))
	}
	if complexities[0].NotCoveredComplexity != 0 {
		t.Fatalf("not_covered_complexity = %d, want 0", complexities[0].NotCoveredComplexity)
	}
}

func TestBranchBlockerSkipsDemangledFallthroughForCpp(t *testing.T) {
	req := request{
		TargetLang: "c-cpp",
		Functions: map[string]functionData{
			"_Z3foov": {
				FunctionSourceFile:        "a.cc",
				CoverageLookupName:        "foo()",
				TotalCyclomaticComplexity: 7,
				BranchProfiles: map[string]branch{
					"a.cc:10,1": {
						Sides: []branchSide{
							{Pos: "a.cc:11,1", Funcs: []string{"_Z3foov"}},
							{Pos: "a.cc:12,1", Funcs: []string{"_Z3foov"}},
						},
					},
				},
			},
		},
		Coverage: coverageData{
			Type:         "function",
			CovMap:       map[string][][]int{"foo()": {{11, 2}}},
			BranchCovMap: map[string][]int{"_Z3foov:10,1": {0, 1}},
		},
	}

	_, blockers := executeRequest(t, req)
	if len(blockers) != 0 {
		t.Fatalf("got %d branch blockers, want 0", len(blockers))
	}
}

func TestBranchBlockerSkipsKernelFallthroughForCpp(t *testing.T) {
	req := request{
		TargetLang: "c-cpp",
		Functions: map[string]functionData{
			"foo": {
				FunctionSourceFile:        "../src/foo.c",
				CoverageLookupName:        "foo",
				TotalCyclomaticComplexity: 5,
				BranchProfiles: map[string]branch{
					"foo.c:10,1": {
						Sides: []branchSide{
							{Pos: "foo.c:11,1", Funcs: []string{"foo"}},
							{Pos: "foo.c:12,1", Funcs: []string{"foo"}},
						},
					},
				},
			},
		},
		Coverage: coverageData{
			Type: "kernel",
			KernelCoverage: []kernelModule{{
				Filename: "/tmp/build/src/foo.c",
				Covered:  []int{15},
			}},
			BranchCovMap: map[string][]int{"foo:10,1": {0, 1}},
		},
	}

	_, blockers := executeRequest(t, req)
	if len(blockers) != 0 {
		t.Fatalf("got %d branch blockers, want 0", len(blockers))
	}
}
