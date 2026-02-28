package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const schemaVersion = 1

type callsite struct {
	CovCtIdx        int    `json:"cov_ct_idx"`
	Depth           int    `json:"depth"`
	DstFunctionName string `json:"dst_function_name"`
	SrcLineNumber   int    `json:"src_linenumber"`
}

type branchSide struct {
	Pos   string   `json:"pos"`
	Funcs []string `json:"funcs"`
}

type branch struct {
	Sides []branchSide `json:"sides"`
}

type functionData struct {
	FunctionSourceFile        string            `json:"function_source_file"`
	TotalCyclomaticComplexity int               `json:"total_cyclomatic_complexity"`
	BranchProfiles            map[string]branch `json:"branch_profiles"`
}

type coverageData struct {
	CovMap       map[string][][]int `json:"covmap"`
	BranchCovMap map[string][]int   `json:"branch_cov_map"`
}

type request struct {
	OutputDir string                  `json:"output_dir"`
	Callsites []callsite              `json:"callsites"`
	Coverage  coverageData            `json:"coverage"`
	Functions map[string]functionData `json:"functions"`
}

type overlayNode struct {
	CovCtIdx              int    `json:"cov_ct_idx"`
	CovHitcount           int    `json:"cov_hitcount"`
	CovColor              string `json:"cov_color"`
	CovLink               string `json:"cov_link"`
	CovCallsiteLink       string `json:"cov_callsite_link"`
	CovForwardReds        int    `json:"cov_forward_reds"`
	CovLargestBlockedFunc string `json:"cov_largest_blocked_func"`
}

type branchComplexity struct {
	FunctionName               string `json:"function_name"`
	Branch                     string `json:"branch"`
	SideIdx                    int    `json:"side_idx"`
	UniqueNotCoveredComplexity int    `json:"unique_not_covered_complexity"`
	UniqueReachableComplexity  int    `json:"unique_reachable_complexity"`
	ReachableComplexity        int    `json:"reachable_complexity"`
	NotCoveredComplexity       int    `json:"not_covered_complexity"`
}

type branchBlocker struct {
	BlockedSide                       string   `json:"blocked_side"`
	BlockedUniqueNotCoveredComplexity int      `json:"blocked_unique_not_covered_complexity"`
	BlockedUniqueReachableComplexity  int      `json:"blocked_unique_reachable_complexity"`
	BlockedUniqueFunctions            []string `json:"blocked_unique_functions"`
	BlockedNotCoveredComplexity       int      `json:"blocked_not_covered_complexity"`
	BlockedReachableComplexity        int      `json:"blocked_reachable_complexity"`
	SidesHitcountDiff                 int      `json:"sides_hitcount_diff"`
	SourceFile                        string   `json:"source_file"`
	BranchLineNumber                  string   `json:"branch_line_number"`
	BlockedSideLineNumder             string   `json:"blocked_side_line_numder"`
	FunctionName                      string   `json:"function_name"`
}

type response struct {
	SchemaVersion int               `json:"schema_version"`
	Status        string            `json:"status"`
	Counters      map[string]int    `json:"counters"`
	Artifacts     map[string]string `json:"artifacts"`
	Timings       map[string]int    `json:"timings"`
	ReasonCode    string            `json:"reason_code,omitempty"`
}

func colorForHitcount(hit int) string {
	if hit <= 0 {
		return "red"
	}
	if hit < 10 {
		return "gold"
	}
	if hit < 30 {
		return "yellow"
	}
	if hit < 50 {
		return "greenyellow"
	}
	return "lawngreen"
}

func writeError(reason string) {
	payload := response{
		SchemaVersion: schemaVersion,
		Status:        "error",
		Counters:      map[string]int{"callsites": 0, "branch_complexities": 0, "branch_blockers": 0},
		Artifacts:     map[string]string{},
		Timings:       map[string]int{},
		ReasonCode:    reason,
	}
	_ = json.NewEncoder(os.Stdout).Encode(payload)
}

func main() {
	if err := run(); err != nil {
		writeError(err.Error())
		os.Exit(1)
	}
}

func run() error {
	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return fmt.Errorf("invalid request json: %w", err)
	}
	if req.OutputDir == "" {
		req.OutputDir = "."
	}
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		return fmt.Errorf("failed creating output_dir: %w", err)
	}

	sort.Slice(req.Callsites, func(i, j int) bool {
		return req.Callsites[i].CovCtIdx < req.Callsites[j].CovCtIdx
	})
	callstack := map[int]string{}
	nodes := make([]overlayNode, 0, len(req.Callsites))
	for idx, cs := range req.Callsites {
		callstack[cs.Depth] = cs.DstFunctionName
		hit := 0
		if idx == 0 {
			for _, pair := range req.Coverage.CovMap[cs.DstFunctionName] {
				if len(pair) == 2 && pair[1] > hit {
					hit = pair[1]
				}
			}
		} else if parent, ok := callstack[cs.Depth-1]; ok {
			for _, pair := range req.Coverage.CovMap[parent] {
				if len(pair) == 2 && pair[0] == cs.SrcLineNumber && pair[1] > 0 {
					hit = pair[1]
					break
				}
			}
		}
		nodes = append(nodes, overlayNode{
			CovCtIdx:              cs.CovCtIdx,
			CovHitcount:           hit,
			CovColor:              colorForHitcount(hit),
			CovLink:               "#",
			CovCallsiteLink:       "#",
			CovForwardReds:        0,
			CovLargestBlockedFunc: "",
		})
	}
	if len(nodes) > 1 {
		for _, n := range nodes[1:] {
			if n.CovHitcount > 0 {
				nodes[0].CovHitcount = 200
				nodes[0].CovColor = colorForHitcount(200)
				break
			}
		}
	}

	complexities := []branchComplexity{}
	fnNames := make([]string, 0, len(req.Functions))
	for name := range req.Functions {
		fnNames = append(fnNames, name)
	}
	sort.Strings(fnNames)
	for _, fnName := range fnNames {
		fn := req.Functions[fnName]
		branches := make([]string, 0, len(fn.BranchProfiles))
		for branchName := range fn.BranchProfiles {
			branches = append(branches, branchName)
		}
		sort.Strings(branches)
		for _, branchName := range branches {
			br := fn.BranchProfiles[branchName]
			for sideIdx, side := range br.Sides {
				complexities = append(complexities, branchComplexity{
					FunctionName:               fnName,
					Branch:                     branchName,
					SideIdx:                    sideIdx,
					UniqueNotCoveredComplexity: 0,
					UniqueReachableComplexity:  0,
					ReachableComplexity:        len(side.Funcs),
					NotCoveredComplexity:       0,
				})
			}
		}
	}

	blockers := []branchBlocker{}
	for branchKey := range req.Coverage.BranchCovMap {
		fnName, lineCol, ok := strings.Cut(branchKey, ":")
		if !ok {
			continue
		}
		line, _, ok := strings.Cut(lineCol, ",")
		if !ok {
			continue
		}
		fn, ok := req.Functions[fnName]
		if !ok {
			continue
		}
		blockers = append(blockers, branchBlocker{
			BlockedSide:                       "0",
			BlockedUniqueNotCoveredComplexity: 0,
			BlockedUniqueReachableComplexity:  0,
			BlockedUniqueFunctions:            []string{},
			BlockedNotCoveredComplexity:       0,
			BlockedReachableComplexity:        0,
			SidesHitcountDiff:                 0,
			SourceFile:                        fn.FunctionSourceFile,
			BranchLineNumber:                  line,
			BlockedSideLineNumder:             line,
			FunctionName:                      fnName,
		})
	}

	overlayPath := filepath.Join(req.OutputDir, "overlay_nodes.json")
	branchComplexityPath := filepath.Join(req.OutputDir, "branch_complexities.json")
	blockerPath := filepath.Join(req.OutputDir, "branch_blockers.json")

	if err := writeJSON(overlayPath, nodes); err != nil {
		return err
	}
	if err := writeJSON(branchComplexityPath, complexities); err != nil {
		return err
	}
	if err := writeJSON(blockerPath, blockers); err != nil {
		return err
	}

	payload := response{
		SchemaVersion: schemaVersion,
		Status:        "success",
		Counters: map[string]int{
			"callsites":           len(nodes),
			"branch_complexities": len(complexities),
			"branch_blockers":     len(blockers),
		},
		Artifacts: map[string]string{
			"overlay_nodes":       overlayPath,
			"branch_complexities": branchComplexityPath,
			"branch_blockers":     blockerPath,
		},
		Timings: map[string]int{"total_ms": 0},
	}
	return json.NewEncoder(os.Stdout).Encode(payload)
}

func writeJSON(path string, value any) error {
	fd, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed creating %s: %w", path, err)
	}
	defer fd.Close()
	enc := json.NewEncoder(fd)
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("failed writing %s: %w", path, err)
	}
	return nil
}
