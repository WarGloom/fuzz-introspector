package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const schemaVersion = 1

type callsite struct {
	CovCtIdx        int    `json:"cov_ct_idx"`
	Depth           int    `json:"depth"`
	DstFunctionName string `json:"dst_function_name"`
	CovLink         string `json:"cov_link"`
	CovCallsiteLink string `json:"cov_callsite_link"`
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
	FileMap      map[string][][]int `json:"file_map"`
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

// splitBranchKey splits on the last colon, then splits the remainder on the
// first comma — equivalent to Rust's rsplit_once(':') + split_once(',').
func splitBranchKey(key string) (fnName, line, col string, ok bool) {
	idx := strings.LastIndex(key, ":")
	if idx < 0 {
		return
	}
	rest := key[idx+1:]
	commaIdx := strings.Index(rest, ",")
	if commaIdx < 0 {
		return
	}
	fnName = key[:idx]
	line = rest[:commaIdx]
	col = rest[commaIdx+1:]
	ok = true
	return
}

// parseSideLine extracts the line number from a branch-side position string
// of the form "file:line,col".
func parseSideLine(pos string) (int, bool) {
	idx := strings.Index(pos, ":")
	if idx < 0 {
		return 0, false
	}
	rest := pos[idx+1:]
	commaIdx := strings.Index(rest, ",")
	if commaIdx < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[:commaIdx])
	if err != nil {
		return 0, false
	}
	return n, true
}

// isSideHit returns true if the given line number has a positive hit count in
// either the file-level coverage map or the function-level coverage map.
func isSideHit(cov coverageData, sourceFile, functionName string, sideLine int) bool {
	if rows, ok := cov.FileMap[sourceFile]; ok {
		for _, row := range rows {
			if len(row) == 2 && row[0] == sideLine && row[1] > 0 {
				return true
			}
		}
		return false
	}
	if rows, ok := cov.CovMap[functionName]; ok {
		for _, row := range rows {
			if len(row) == 2 && row[0] == sideLine && row[1] > 0 {
				return true
			}
		}
	}
	return false
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
			CovLink:               cs.CovLink,
			CovCallsiteLink:       cs.CovCallsiteLink,
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

	prevEnd := -1
	for idx := range nodes {
		prevDepthLEQ := false
		if idx > 0 {
			prevDepthLEQ = req.Callsites[idx-1].Depth <= req.Callsites[idx].Depth
		}
		if nodes[idx].CovHitcount == 0 && (prevDepthLEQ || idx < prevEnd) {
			nodes[idx].CovForwardReds = 0
			nodes[idx].CovLargestBlockedFunc = "none"
			continue
		}

		forwardRed := 0
		largestBlockedName := ""
		largestBlockedCount := 0
		lookAhead := idx + 1
		for lookAhead < len(nodes) {
			n2 := nodes[lookAhead]
			if n2.CovHitcount != 0 {
				break
			}

			lookName := req.Callsites[lookAhead].DstFunctionName
			if fd, ok := req.Functions[lookName]; ok {
				if fd.TotalCyclomaticComplexity > largestBlockedCount {
					largestBlockedCount = fd.TotalCyclomaticComplexity
					largestBlockedName = lookName
				}
			}

			forwardRed++
			lookAhead++
		}
		prevEnd = lookAhead - 1
		nodes[idx].CovForwardReds = forwardRed
		nodes[idx].CovLargestBlockedFunc = largestBlockedName
	}

	// ── Branch complexity ────────────────────────────────────────────────────
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
				otherSideFuncs := map[string]struct{}{}
				for iterIdx, iterSide := range br.Sides {
					if iterIdx == sideIdx {
						continue
					}
					for _, f := range iterSide.Funcs {
						otherSideFuncs[f] = struct{}{}
					}
				}
				uniqueFuncs := map[string]struct{}{}
				for _, f := range side.Funcs {
					if _, inOther := otherSideFuncs[f]; !inOther {
						uniqueFuncs[f] = struct{}{}
					}
				}

				var reachable, uniqueReachable, notCovered, uniqueNotCovered int
				for _, f := range side.Funcs {
					complexity := 0
					if fd, ok := req.Functions[f]; ok {
						complexity = fd.TotalCyclomaticComplexity
					}
					reachable += complexity
					if _, isUniq := uniqueFuncs[f]; isUniq {
						uniqueReachable += complexity
					}
					isHit := false
					if rows, ok := req.Coverage.CovMap[f]; ok {
						for _, row := range rows {
							if len(row) == 2 && row[1] > 0 {
								isHit = true
								break
							}
						}
					}
					if !isHit {
						notCovered += complexity
						if _, isUniq := uniqueFuncs[f]; isUniq {
							uniqueNotCovered += complexity
						}
					}
				}
				complexities = append(complexities, branchComplexity{
					FunctionName:               fnName,
					Branch:                     branchName,
					SideIdx:                    sideIdx,
					UniqueNotCoveredComplexity: uniqueNotCovered,
					UniqueReachableComplexity:  uniqueReachable,
					ReachableComplexity:        reachable,
					NotCoveredComplexity:       notCovered,
				})
			}
		}
	}
	sort.Slice(complexities, func(i, j int) bool {
		a, b := complexities[i], complexities[j]
		if a.FunctionName != b.FunctionName {
			return a.FunctionName < b.FunctionName
		}
		if a.Branch != b.Branch {
			return a.Branch < b.Branch
		}
		return a.SideIdx < b.SideIdx
	})

	// ── Complexity lookup map ────────────────────────────────────────────────
	type complexityKey struct {
		fnName  string
		branch  string
		sideIdx int
	}
	complexityLookup := map[complexityKey]*branchComplexity{}
	for i := range complexities {
		c := &complexities[i]
		complexityLookup[complexityKey{c.FunctionName, c.Branch, c.SideIdx}] = c
	}

	// ── Branch blockers ──────────────────────────────────────────────────────
	blockers := []branchBlocker{}
	for branchKey, sideHitsRaw := range req.Coverage.BranchCovMap {
		sideHits := make([]int, len(sideHitsRaw))
		copy(sideHits, sideHitsRaw)
		branchHitcount := -1
		if len(sideHits) > 2 {
			// first two entries are the switch preamble; strip them
			max0, max1 := sideHits[0], sideHits[1]
			if max1 > max0 {
				branchHitcount = max1
			} else {
				branchHitcount = max0
			}
			sideHits = sideHits[2:]
		}

		fnName, lineStr, colStr, ok := splitBranchKey(branchKey)
		if !ok {
			continue
		}
		fn, ok := req.Functions[fnName]
		if !ok {
			continue
		}
		llvmBranch := filepath.Base(fn.FunctionSourceFile) + ":" + lineStr + "," + colStr
		br, ok := fn.BranchProfiles[llvmBranch]
		if !ok {
			continue
		}
		if len(sideHits) != len(br.Sides) {
			continue
		}

		taken := false
		var notTakenIndices []int
		for idx, hit := range sideHits {
			if hit == 0 {
				notTakenIndices = append(notTakenIndices, idx)
			} else {
				taken = true
			}
		}
		if !taken || len(notTakenIndices) == 0 {
			continue
		}

		for _, blockedIdx := range notTakenIndices {
			side := br.Sides[blockedIdx]
			blockedLine, ok := parseSideLine(side.Pos)
			if !ok {
				continue
			}
			branchLine, _ := strconv.Atoi(lineStr)
			if branchLine > blockedLine {
				continue
			}
			if isSideHit(req.Coverage, fn.FunctionSourceFile, fnName, blockedLine) {
				continue
			}

			key := complexityKey{fnName, llvmBranch, blockedIdx}
			comp, ok := complexityLookup[key]
			if !ok {
				continue
			}

			otherSideFuncs := map[string]struct{}{}
			for iterIdx, iterSide := range br.Sides {
				if iterIdx == blockedIdx {
					continue
				}
				for _, f := range iterSide.Funcs {
					otherSideFuncs[f] = struct{}{}
				}
			}
			var uniqueFuncsList []string
			for _, f := range side.Funcs {
				if _, inOther := otherSideFuncs[f]; !inOther {
					uniqueFuncsList = append(uniqueFuncsList, f)
				}
			}
			if uniqueFuncsList == nil {
				uniqueFuncsList = []string{}
			}

			maxHit := branchHitcount
			for _, h := range sideHits {
				if h > maxHit {
					maxHit = h
				}
			}

			blockers = append(blockers, branchBlocker{
				BlockedSide:                       strconv.Itoa(blockedIdx),
				BlockedUniqueNotCoveredComplexity: comp.UniqueNotCoveredComplexity,
				BlockedUniqueReachableComplexity:  comp.UniqueReachableComplexity,
				BlockedUniqueFunctions:            uniqueFuncsList,
				BlockedNotCoveredComplexity:       comp.NotCoveredComplexity,
				BlockedReachableComplexity:        comp.ReachableComplexity,
				SidesHitcountDiff:                 maxHit,
				SourceFile:                        fn.FunctionSourceFile,
				BranchLineNumber:                  lineStr,
				BlockedSideLineNumder:             strconv.Itoa(blockedLine),
				FunctionName:                      fnName,
			})
		}
	}
	sort.Slice(blockers, func(i, j int) bool {
		a, b := blockers[i], blockers[j]
		if a.BlockedUniqueNotCoveredComplexity != b.BlockedUniqueNotCoveredComplexity {
			return a.BlockedUniqueNotCoveredComplexity > b.BlockedUniqueNotCoveredComplexity
		}
		if a.BlockedUniqueReachableComplexity != b.BlockedUniqueReachableComplexity {
			return a.BlockedUniqueReachableComplexity > b.BlockedUniqueReachableComplexity
		}
		if a.BlockedNotCoveredComplexity != b.BlockedNotCoveredComplexity {
			return a.BlockedNotCoveredComplexity > b.BlockedNotCoveredComplexity
		}
		return a.BlockedReachableComplexity > b.BlockedReachableComplexity
	})

	overlayPath := filepath.Join(req.OutputDir, "overlay_nodes.json")
	branchComplexityPath := filepath.Join(req.OutputDir, "branch_complexities.json")
	blockerPath := filepath.Join(req.OutputDir, "branch_blockers.json")

	errs := make([]error, 3)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); errs[0] = writeJSON(overlayPath, nodes) }()
	go func() { defer wg.Done(); errs[1] = writeJSON(branchComplexityPath, complexities) }()
	go func() { defer wg.Done(); errs[2] = writeJSON(blockerPath, blockers) }()
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
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
