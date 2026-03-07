package main

import "testing"

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
