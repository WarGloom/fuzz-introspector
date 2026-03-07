package main

import "testing"

func TestExtractHitCountParsesSuffixesAndScientificNotation(t *testing.T) {
	cases := []struct {
		input string
		want  int
		ok    bool
	}{
		{"12", 12, true},
		{"1.5k", 1500, true},
		{"2M", 2000000, true},
		{"1.2E3", 1200, true},
		{"bogus", 0, false},
	}
	for _, tc := range cases {
		got, ok := extractHitCount(tc.input)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("extractHitCount(%q) = (%d, %v), want (%d, %v)", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseBranchLineExtractsLocationAndCounts(t *testing.T) {
	lineNumber, columnNumber, trueHit, falseHit, ok := parseBranchLine("  |  Branch (17:9): [True: 10, False: 2]")
	if !ok {
		t.Fatal("parseBranchLine() returned ok=false")
	}
	if lineNumber != 17 || columnNumber != 9 || trueHit != 10 || falseHit != 2 {
		t.Fatalf("parseBranchLine() = (%d, %d, %d, %d)", lineNumber, columnNumber, trueHit, falseHit)
	}
}

func TestExtractFunctionNameCompactsAnnotatedLine(t *testing.T) {
	got := extractFunctionName("prefix:my_function:")
	if got != "my_function" {
		t.Fatalf("extractFunctionName() = %q, want %q", got, "my_function")
	}
}

func TestCoverageLineDetectors(t *testing.T) {
	if !isSwitchCoverageLine("  9|  10| switch(value)") {
		t.Fatal("isSwitchCoverageLine() returned false for switch line")
	}
	if !isCaseCoverageLine(" 10|   0| case 1:") {
		t.Fatal("isCaseCoverageLine() returned false for case line")
	}
	if !isBranchCoverageLine(" 11|   2| Branch (11:4): [True: 1, False: 1]") {
		t.Fatal("isBranchCoverageLine() returned false for branch line")
	}
}
