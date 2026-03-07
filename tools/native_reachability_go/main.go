package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

const schemaVersion = 1

type inputPayload struct {
	SchemaVersion int            `json:"schema_version"`
	Profiles      []profileInput `json:"profiles"`
}

type profileInput struct {
	ProfileID string          `json:"profile_id"`
	Functions []functionInput `json:"functions"`
}

type functionInput struct {
	Name          string   `json:"name"`
	DirectCallees []string `json:"direct_callees"`
}

type outputPayload struct {
	SchemaVersion int             `json:"schema_version"`
	Status        string          `json:"status"`
	Profiles      []profileOutput `json:"profiles,omitempty"`
	Reason        string          `json:"reason,omitempty"`
}

type profileOutput struct {
	ProfileID string           `json:"profile_id"`
	Results   []functionResult `json:"results"`
}

type functionResult struct {
	Name             string   `json:"name"`
	FunctionsReached []string `json:"functions_reached"`
	FunctionDepth    int      `json:"function_depth"`
}

type frame struct {
	Node     string
	Children []string
	ChildIdx int
}

func computeReachability(functions []functionInput) []functionResult {
	adjacency := make(map[string][]string, len(functions))
	allNodes := make([]string, 0, len(functions))
	seenNodes := make(map[string]bool, len(functions))

	for _, function := range functions {
		adjacency[function.Name] = append([]string{}, function.DirectCallees...)
		if !seenNodes[function.Name] {
			seenNodes[function.Name] = true
			allNodes = append(allNodes, function.Name)
		}
		for _, callee := range function.DirectCallees {
			if !seenNodes[callee] {
				seenNodes[callee] = true
				allNodes = append(allNodes, callee)
			}
		}
	}
	for _, node := range allNodes {
		if _, ok := adjacency[node]; !ok {
			adjacency[node] = []string{}
		}
	}

	indexMap := map[string]int{}
	lowLink := map[string]int{}
	onStack := map[string]bool{}
	tarjanStack := make([]string, 0, len(allNodes))
	sccs := make([][]string, 0)
	indexCounter := 0

	for _, start := range allNodes {
		if _, ok := indexMap[start]; ok {
			continue
		}

		indexMap[start] = indexCounter
		lowLink[start] = indexCounter
		indexCounter++
		tarjanStack = append(tarjanStack, start)
		onStack[start] = true
		callStack := []frame{{Node: start, Children: append([]string{}, adjacency[start]...)}}

		for len(callStack) > 0 {
			lastIndex := len(callStack) - 1
			current := &callStack[lastIndex]
			if current.ChildIdx < len(current.Children) {
				child := current.Children[current.ChildIdx]
				current.ChildIdx++
				if _, ok := indexMap[child]; !ok {
					indexMap[child] = indexCounter
					lowLink[child] = indexCounter
					indexCounter++
					tarjanStack = append(tarjanStack, child)
					onStack[child] = true
					callStack = append(callStack, frame{Node: child, Children: append([]string{}, adjacency[child]...)})
					continue
				}
				if onStack[child] && indexMap[child] < lowLink[current.Node] {
					lowLink[current.Node] = indexMap[child]
				}
				continue
			}

			node := current.Node
			callStack = callStack[:lastIndex]
			if len(callStack) > 0 {
				parent := callStack[len(callStack)-1].Node
				if lowLink[node] < lowLink[parent] {
					lowLink[parent] = lowLink[node]
				}
			}
			if lowLink[node] == indexMap[node] {
				scc := make([]string, 0)
				for {
					stackLast := len(tarjanStack) - 1
					popped := tarjanStack[stackLast]
					tarjanStack = tarjanStack[:stackLast]
					onStack[popped] = false
					scc = append(scc, popped)
					if popped == node {
						break
					}
				}
				sccs = append(sccs, scc)
			}
		}
	}

	sccID := make(map[string]int, len(allNodes))
	for index, scc := range sccs {
		for _, name := range scc {
			sccID[name] = index
		}
	}

	sccSuccessors := make([]map[int]bool, len(sccs))
	for idx := range sccSuccessors {
		sccSuccessors[idx] = map[int]bool{}
	}
	for _, node := range allNodes {
		nodeSCC := sccID[node]
		for _, callee := range adjacency[node] {
			calleeSCC, ok := sccID[callee]
			if ok && calleeSCC != nodeSCC {
				sccSuccessors[nodeSCC][calleeSCC] = true
			}
		}
	}

	sccReachable := make([]map[string]bool, len(sccs))
	sccDepth := make([]int, len(sccs))
	for index, scc := range sccs {
		reachable := make(map[string]bool, len(scc))
		for _, name := range scc {
			reachable[name] = true
		}
		maxDepth := 0
		for successor := range sccSuccessors[index] {
			for name := range sccReachable[successor] {
				reachable[name] = true
			}
			if candidateDepth := sccDepth[successor] + 1; candidateDepth > maxDepth {
				maxDepth = candidateDepth
			}
		}
		sccReachable[index] = reachable
		sccDepth[index] = maxDepth
	}

	results := make([]functionResult, 0, len(functions))
	for _, function := range functions {
		sid, ok := sccID[function.Name]
		if !ok {
			results = append(results, functionResult{Name: function.Name})
			continue
		}
		reached := make([]string, 0, len(sccReachable[sid]))
		for name := range sccReachable[sid] {
			if name != function.Name {
				reached = append(reached, name)
			}
		}
		sort.Strings(reached)
		results = append(results, functionResult{
			Name:             function.Name,
			FunctionsReached: reached,
			FunctionDepth:    sccDepth[sid],
		})
	}
	return results
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

	profiles := make([]profileOutput, 0, len(payload.Profiles))
	for _, profile := range payload.Profiles {
		profiles = append(profiles, profileOutput{
			ProfileID: profile.ProfileID,
			Results:   computeReachability(profile.Functions),
		})
	}

	writeJSON(outputPayload{
		SchemaVersion: schemaVersion,
		Status:        "success",
		Profiles:      profiles,
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
