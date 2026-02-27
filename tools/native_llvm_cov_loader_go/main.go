package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type inputPayload struct {
	CoverageReports []string `json:"coverage_reports"`
}

type outputPayload struct {
	CovMap        map[string][][]int `json:"covmap"`
	BranchCovMap  map[string][]int   `json:"branch_cov_map"`
	CoverageFiles []string           `json:"coverage_files"`
}

func extractHitCount(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}

	// Scientific notation, e.g. 1.2E6
	if strings.ContainsAny(raw, "eE") {
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return 0, false
		}
		return int(f), true
	}

	last := raw[len(raw)-1]
	if last >= '0' && last <= '9' {
		val, err := strconv.Atoi(raw)
		if err != nil {
			return 0, false
		}
		return val, true
	}

	multiplier := 1.0
	switch last {
	case 'k':
		multiplier = 1000
	case 'M':
		multiplier = 1000000
	case 'G':
		multiplier = 1000000000
	default:
		return 0, false
	}

	numPart := raw[:len(raw)-1]
	f, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, false
	}
	return int(f * multiplier), true
}

func parseBranchLine(line string) (int, int, int, int, bool) {
	branchStart := strings.Index(line, "Branch (")
	if branchStart == -1 {
		return 0, 0, 0, 0, false
	}
	branchStart += len("Branch (")

	branchEndOffset := strings.IndexByte(line[branchStart:], ')')
	if branchEndOffset == -1 {
		return 0, 0, 0, 0, false
	}
	branchEnd := branchStart + branchEndOffset
	location := line[branchStart:branchEnd]
	colonOffset := strings.IndexByte(location, ':')
	if colonOffset == -1 {
		return 0, 0, 0, 0, false
	}

	lineNumber, err := strconv.Atoi(strings.TrimSpace(location[:colonOffset]))
	if err != nil {
		return 0, 0, 0, 0, false
	}
	columnNumber, err := strconv.Atoi(strings.TrimSpace(location[colonOffset+1:]))
	if err != nil {
		return 0, 0, 0, 0, false
	}

	trueStart := strings.Index(line, "True:")
	falseStart := strings.Index(line, "False:")
	if trueStart == -1 || falseStart == -1 {
		return 0, 0, 0, 0, false
	}
	trueValueStart := trueStart + len("True:")
	commaOffset := strings.IndexByte(line[trueValueStart:], ',')
	if commaOffset == -1 {
		return 0, 0, 0, 0, false
	}

	trueRaw := strings.TrimSpace(line[trueValueStart : trueValueStart+commaOffset])
	falseRaw := line[falseStart+len("False:"):]
	if endOffset := strings.IndexByte(falseRaw, ']'); endOffset != -1 {
		falseRaw = falseRaw[:endOffset]
	}
	falseRaw = strings.TrimSpace(falseRaw)

	trueHit, ok := extractHitCount(trueRaw)
	if !ok {
		return 0, 0, 0, 0, false
	}
	falseHit, ok := extractHitCount(falseRaw)
	if !ok {
		return 0, 0, 0, 0, false
	}

	return lineNumber, columnNumber, trueHit, falseHit, true
}

func extractFunctionName(line string) string {
	segment := line
	firstColon := -1
	secondColon := -1
	colonCount := 0
	for idx := 0; idx < len(line); idx++ {
		if line[idx] != ':' {
			continue
		}
		colonCount++
		if firstColon == -1 {
			firstColon = idx
		} else if secondColon == -1 {
			secondColon = idx
		}
	}
	if colonCount == 2 {
		segment = line[firstColon+1 : secondColon]
	}

	compact := make([]byte, 0, len(segment))
	for idx := 0; idx < len(segment); idx++ {
		if segment[idx] == ' ' || segment[idx] == ':' {
			continue
		}
		compact = append(compact, segment[idx])
	}
	return string(compact)
}

func parseCoverageColumns(line string) (int, string, string, bool) {
	firstPipe := strings.IndexByte(line, '|')
	if firstPipe == -1 {
		return 0, "", "", false
	}

	lineNo, err := strconv.Atoi(strings.TrimSpace(line[:firstPipe]))
	if err != nil {
		return 0, "", "", false
	}

	secondPipeOffset := strings.IndexByte(line[firstPipe+1:], '|')
	if secondPipeOffset == -1 {
		return lineNo, line[firstPipe+1:], "", true
	}
	secondPipe := firstPipe + 1 + secondPipeOffset
	return lineNo, line[firstPipe+1 : secondPipe], line[secondPipe+1:], true
}

func isSwitchCoverageLine(line string) bool {
	if !strings.Contains(line, "|") ||
		!strings.Contains(line, "switch") {
		return false
	}

	switchStart := strings.Index(line, "switch")
	if switchStart <= 0 {
		return false
	}
	leading := line[switchStart-1]
	if leading != ' ' && leading != '\t' {
		return false
	}

	openOffset := strings.IndexByte(line[switchStart:], '(')
	if openOffset == -1 {
		return false
	}
	openParen := switchStart + openOffset
	return strings.IndexByte(line[openParen+1:], ')') != -1
}

func isCaseCoverageLine(line string) bool {
	if !strings.Contains(line, "|") ||
		!strings.Contains(line, "case") {
		return false
	}

	caseStart := strings.Index(line, "case")
	if caseStart <= 0 {
		return false
	}
	leading := line[caseStart-1]
	if leading != ' ' && leading != '\t' {
		return false
	}

	return strings.IndexByte(line[caseStart+len("case"):], ':') != -1
}

func isBranchCoverageLine(line string) bool {
	if !strings.Contains(line, "|") ||
		!strings.Contains(line, "Branch") {
		return false
	}

	branchStart := strings.Index(line, "Branch")
	if branchStart <= 0 {
		return false
	}
	leading := line[branchStart-1]
	if leading != ' ' && leading != '\t' {
		return false
	}

	openOffset := strings.IndexByte(line[branchStart:], '(')
	if openOffset == -1 {
		return false
	}
	openParen := branchStart + openOffset

	closeOffset := strings.IndexByte(line[openParen+1:], ')')
	if closeOffset == -1 {
		return false
	}
	closeParen := openParen + 1 + closeOffset
	if closeParen+1 >= len(line) || line[closeParen+1] != ':' {
		return false
	}
	return strings.IndexByte(line[openParen+1:closeParen], ':') != -1
}

func makeCoverageKey(functionName string, lineNo int, columnNo int) string {
	return functionName + ":" + strconv.Itoa(lineNo) + "," + strconv.Itoa(columnNo)
}

func parseCoverageReport(path string, out *outputPayload) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	currentFunc := ""
	currentFuncCoverage := make([][]int, 0, 64)
	switchString := ""
	switchLineNumber := -1
	caseLineNumbers := make(map[int]struct{}, 16)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Function marker line:
		//   LLVMFuzzerTestOneInput:
		if len(line) > 0 && line[len(line)-1] == ':' && !strings.Contains(line, "|") {
			if currentFunc != "" {
				out.CovMap[currentFunc] = currentFuncCoverage
			}
			currentFunc = extractFunctionName(line)
			switchString = ""
			switchLineNumber = -1
			clear(caseLineNumbers)
			if existing, exists := out.CovMap[currentFunc]; exists {
				currentFuncCoverage = existing[:0]
			} else {
				currentFuncCoverage = make([][]int, 0, 64)
			}
			continue
		}

		if currentFunc == "" {
			continue
		}

		if isBranchCoverageLine(line) {
			branchLine, branchCol, trueHit, falseHit, ok := parseBranchLine(line)
			if ok {
				if switchLineNumber > 0 && branchLine == switchLineNumber {
					out.BranchCovMap[switchString] = []int{trueHit, falseHit}
				} else if _, seenCase := caseLineNumbers[branchLine]; seenCase {
					existing, exists := out.BranchCovMap[switchString]
					if !exists {
						out.BranchCovMap[switchString] = []int{trueHit, falseHit, trueHit}
					} else {
						out.BranchCovMap[switchString] = append(existing, trueHit)
					}
				} else {
					branchKey := makeCoverageKey(currentFunc, branchLine, branchCol)
					out.BranchCovMap[branchKey] = []int{trueHit, falseHit}
				}
			}
		}

		lineNo, rawHitCount, sourceFragment, ok := parseCoverageColumns(line)
		if !ok {
			continue
		}

		if isSwitchCoverageLine(line) {
			columnNumber := strings.Index(sourceFragment, "switch") + 1
			switchLineNumber = lineNo
			clear(caseLineNumbers)
			switchString = makeCoverageKey(currentFunc, lineNo, columnNumber)
		}
		if isCaseCoverageLine(line) {
			if switchString != "" {
				caseLineNumbers[lineNo] = struct{}{}
			}
		}

		hitCount, ok := extractHitCount(rawHitCount)
		if !ok {
			// Keep parity with python behavior for explicit zero forms.
			if strings.Contains(line, " 0| ") {
				hitCount = 0
			} else {
				continue
			}
		}

		currentFuncCoverage = append(currentFuncCoverage, []int{lineNo, hitCount})
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	if currentFunc != "" {
		out.CovMap[currentFunc] = currentFuncCoverage
	}
	return nil
}

func run() error {
	rawInput, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed reading stdin: %w", err)
	}

	var input inputPayload
	if err := json.Unmarshal(rawInput, &input); err != nil {
		return fmt.Errorf("failed parsing input payload: %w", err)
	}

	output := outputPayload{
		CovMap:        map[string][][]int{},
		BranchCovMap:  map[string][]int{},
		CoverageFiles: append([]string{}, input.CoverageReports...),
	}

	for _, reportPath := range input.CoverageReports {
		if err := parseCoverageReport(reportPath, &output); err != nil {
			return fmt.Errorf("failed parsing coverage report %s: %w", reportPath, err)
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed writing output payload: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
