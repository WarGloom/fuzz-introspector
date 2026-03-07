package main

import (
	"encoding/json"
	"testing"
)

func sampleRequest(pluginNames ...string) request {
	projectData := map[string]any{
		"target_lang": "c-cpp",
		"functions": []map[string]any{
			{
				"name":                        "foo",
				"hitcount":                    0,
				"arg_count":                   2,
				"cyclomatic_complexity":       25,
				"total_cyclomatic_complexity": 80,
				"new_unreached_complexity":    60,
				"bb_count":                    5,
				"functions_reached_count":     2,
				"source_file":                 "foo.cpp",
				"incoming_references":         []string{"driver"},
			},
			{
				"name":                        "driver",
				"hitcount":                    1,
				"arg_count":                   1,
				"cyclomatic_complexity":       10,
				"total_cyclomatic_complexity": 30,
				"new_unreached_complexity":    25,
				"bb_count":                    3,
				"reached_by_fuzzers":          []string{"fuzzer1"},
				"runtime_coverage_percent":    10.0,
				"source_file":                 "driver.cpp",
			},
			{
				"name":                     "std::system",
				"source_file":              "sink.cpp",
				"incoming_references":      []string{"driver"},
				"reached_by_fuzzers":       []string{"fuzzer1"},
				"runtime_coverage_percent": 0.0,
			},
		},
	}
	rawProjectData, _ := json.Marshal(projectData)
	return request{SchemaVersion: 1, Plugins: pluginNames, ProjectData: rawProjectData}
}

func TestRunRequestReturnsRowsForKnownPlugins(t *testing.T) {
	results, err := runRequest(sampleRequest(
		"optimal_targets",
		"runtime_coverage_analysis",
		"calltree_analysis",
		"function_table",
		"far_reach_low_coverage_analysis",
	))
	if err != nil {
		t.Fatalf("runRequest() error = %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("runRequest() returned %d results, want 5", len(results))
	}
	if len(results["optimal_targets"].Tables["optimal_targets"]) != 1 {
		t.Fatalf("optimal_targets rows = %d, want 1", len(results["optimal_targets"].Tables["optimal_targets"]))
	}
	if len(results["runtime_coverage_analysis"].Tables["runtime_coverage"]) != 1 {
		t.Fatalf("runtime_coverage rows = %d, want 1", len(results["runtime_coverage_analysis"].Tables["runtime_coverage"]))
	}
	if len(results["calltree_analysis"].Tables["calltree_nodes"]) != 1 {
		t.Fatalf("calltree_nodes rows = %d, want 1", len(results["calltree_analysis"].Tables["calltree_nodes"]))
	}
}

func TestRunRequestOmitsUnknownPlugin(t *testing.T) {
	results, err := runRequest(sampleRequest("unknown_plugin"))
	if err != nil {
		t.Fatalf("runRequest() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("runRequest() returned %d results, want 0", len(results))
	}
}

func TestRunSinkCoverageAnalysisUsesEmbeddedSinkData(t *testing.T) {
	results, err := runRequest(sampleRequest("sink_coverage_analysis"))
	if err != nil {
		t.Fatalf("runRequest() error = %v", err)
	}
	rows := results["sink_coverage_analysis"].Tables["sink_coverage"]
	if len(rows) != 1 {
		t.Fatalf("sink_coverage rows = %d, want 1", len(rows))
	}
	row := rows[0].(map[string]any)
	if row["func_name"] != "std::system" {
		t.Fatalf("func_name = %v, want std::system", row["func_name"])
	}
	if row["cwe"] != "CWE78" {
		t.Fatalf("cwe = %v, want CWE78", row["cwe"])
	}
}
