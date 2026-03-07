package main

import "testing"

func TestComputeReachabilityHandlesCyclesWithoutTruncation(t *testing.T) {
	results := computeReachability([]functionInput{
		{Name: "entry", DirectCallees: []string{"cycle_a"}},
		{Name: "cycle_a", DirectCallees: []string{"cycle_b"}},
		{Name: "cycle_b", DirectCallees: []string{"cycle_a", "leaf"}},
		{Name: "leaf", DirectCallees: nil},
	})

	resultMap := map[string]functionResult{}
	for _, result := range results {
		resultMap[result.Name] = result
	}

	entry := resultMap["entry"]
	if entry.FunctionDepth != 2 {
		t.Fatalf("entry depth = %d, want 2", entry.FunctionDepth)
	}
	if len(entry.FunctionsReached) != 3 {
		t.Fatalf("entry reached %v, want 3 reachable functions", entry.FunctionsReached)
	}

	cycleA := resultMap["cycle_a"]
	if cycleA.FunctionDepth != 1 {
		t.Fatalf("cycle_a depth = %d, want 1", cycleA.FunctionDepth)
	}
	if len(cycleA.FunctionsReached) != 2 || cycleA.FunctionsReached[0] != "cycle_b" || cycleA.FunctionsReached[1] != "leaf" {
		t.Fatalf("cycle_a reached = %v", cycleA.FunctionsReached)
	}

	cycleB := resultMap["cycle_b"]
	if len(cycleB.FunctionsReached) != 2 || cycleB.FunctionsReached[0] != "cycle_a" || cycleB.FunctionsReached[1] != "leaf" {
		t.Fatalf("cycle_b reached = %v", cycleB.FunctionsReached)
	}
}

func TestComputeReachabilityIncludesExternalCallees(t *testing.T) {
	results := computeReachability([]functionInput{{
		Name:          "entry",
		DirectCallees: []string{"external_target"},
	}})
	if len(results) != 1 {
		t.Fatalf("computeReachability() returned %d results, want 1", len(results))
	}
	if len(results[0].FunctionsReached) != 1 || results[0].FunctionsReached[0] != "external_target" {
		t.Fatalf("entry reached = %v", results[0].FunctionsReached)
	}
}
