package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func parsePyYAMLBool(value string) (any, bool) {
	switch value {
	case "yes", "Yes", "YES", "on", "On", "ON", "true", "True", "TRUE":
		return true, true
	case "no", "No", "NO", "off", "Off", "OFF", "false", "False", "FALSE":
		return false, true
	default:
		return nil, false
	}
}

func validateUnderscoreSeparatedDigits(value string,
	isAllowedDigit func(rune) bool) bool {
	if value == "" {
		return false
	}
	previousUnderscore := true
	seenDigit := false
	for _, ch := range value {
		if ch == '_' {
			if previousUnderscore {
				return false
			}
			previousUnderscore = true
			continue
		}
		if !isAllowedDigit(ch) {
			return false
		}
		previousUnderscore = false
		seenDigit = true
	}
	return seenDigit && !previousUnderscore
}

func isDigitUnderscore(value string) bool {
	return validateUnderscoreSeparatedDigits(value, func(ch rune) bool {
		return ch >= '0' && ch <= '9'
	})
}

func isOctalDigitUnderscore(value string) bool {
	return validateUnderscoreSeparatedDigits(value, func(ch rune) bool {
		return ch >= '0' && ch <= '7'
	})
}

func parsePyYAMLInt(value string) (any, bool) {
	if value == "" {
		return nil, false
	}
	sign := int64(1)
	body := value
	if strings.HasPrefix(body, "+") {
		body = body[1:]
	} else if strings.HasPrefix(body, "-") {
		sign = -1
		body = body[1:]
	}
	if body == "" {
		return nil, false
	}

	base := 10
	digits := body
	switch {
	case strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X"):
		base = 16
		digits = body[2:]
	case strings.HasPrefix(body, "0b") || strings.HasPrefix(body, "0B"):
		base = 2
		digits = body[2:]
	case len(body) > 1 && body[0] == '0':
		// PyYAML safe_load follows YAML 1.1 octal resolution for plain scalars.
		if !isOctalDigitUnderscore(body) {
			return nil, false
		}
		base = 8
		digits = body
	default:
		if !isDigitUnderscore(body) {
			return nil, false
		}
	}
	if digits == "" {
		return nil, false
	}
	if strings.Trim(digits, "_") == "" {
		return nil, false
	}

	cleanDigits := strings.ReplaceAll(digits, "_", "")
	if sign < 0 {
		unsignedValue, err := strconv.ParseUint(cleanDigits, base, 64)
		if err != nil || unsignedValue > math.MaxInt64+1 {
			return nil, false
		}
		if unsignedValue == math.MaxInt64+1 {
			return int64(math.MinInt64), true
		}
		return -int64(unsignedValue), true
	}

	signedValue, err := strconv.ParseInt(cleanDigits, base, 64)
	if err == nil {
		return signedValue, true
	}
	unsignedValue, unsignedErr := strconv.ParseUint(cleanDigits, base, 64)
	if unsignedErr != nil {
		return nil, false
	}
	return unsignedValue, true
}

func parsePyYAMLScalar(value string) (any, bool) {
	if parsedBool, ok := parsePyYAMLBool(value); ok {
		return parsedBool, true
	}
	if parsedInt, ok := parsePyYAMLInt(value); ok {
		return parsedInt, true
	}
	return nil, false
}

func normalizeYAML(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, rawValue := range typed {
			result[key] = normalizeYAML(rawValue)
		}
		return result
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, rawValue := range typed {
			result[fmt.Sprint(key)] = normalizeYAML(rawValue)
		}
		return result
	case []any:
		result := make([]any, 0, len(typed))
		for _, elem := range typed {
			result = append(result, normalizeYAML(elem))
		}
		return result
	case string:
		if resolved, ok := parsePyYAMLScalar(typed); ok {
			return resolved
		}
		return typed
	default:
		return typed
	}
}

func loadYAML(path string) (any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var payload any
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	return normalizeYAML(payload), nil
}

func appendPythonExtend(items []any, parsed any) ([]any, bool) {
	switch typed := parsed.(type) {
	case nil:
		return items, true
	case bool:
		if !typed {
			return items, true
		}
		return items, false
	case string:
		if typed == "" {
			return items, true
		}
		for _, runeValue := range typed {
			items = append(items, string(runeValue))
		}
		return items, true
	case []any:
		for _, elem := range typed {
			items = append(items, elem)
		}
		return items, true
	case map[string]any:
		if len(typed) == 0 {
			return items, true
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			items = append(items, key)
		}
		return items, true
	default:
		return items, false
	}
}

func parsePayload(rawInput []byte) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal(rawInput, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func parseStringSlice(rawValue any) ([]string, error) {
	rawSlice, ok := rawValue.([]any)
	if !ok {
		return nil, errors.New("paths must be an array")
	}

	paths := make([]string, 0, len(rawSlice))
	for _, elem := range rawSlice {
		path, ok := elem.(string)
		if !ok {
			return nil, errors.New("paths must be an array of strings")
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func writeJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func run() error {
	rawInput, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	payload, err := parsePayload(rawInput)
	if err != nil {
		return err
	}

	if rawPath, ok := payload["path"]; ok {
		path, ok := rawPath.(string)
		if !ok || path == "" {
			return errors.New("invalid path payload")
		}
		parsed, err := loadYAML(path)
		if err != nil {
			return writeJSON(nil)
		}
		return writeJSON(parsed)
	}

	rawPaths, ok := payload["paths"]
	if !ok {
		return errors.New("expected path or paths payload")
	}

	paths, err := parseStringSlice(rawPaths)
	if err != nil {
		return err
	}

	items := make([]any, 0)
	for _, path := range paths {
		parsed, loadErr := loadYAML(path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "failed to parse %s: %v\n", path, loadErr)
			continue
		}
		var extended bool
		items, extended = appendPythonExtend(items, parsed)
		if !extended {
			fmt.Fprintf(os.Stderr,
				"skipping non-iterable payload in %s\n", path)
		}
	}

	return writeJSON(map[string]any{"items": items})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
