// Copyright 2025 Fuzz Introspector Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Unit tests for pure-logic helpers in main.go.
// Run from the module directory:
//
//	go test -v ./...
package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// normalizeSignedDecimal
// ---------------------------------------------------------------------------

func TestNormalizeSignedDecimal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantStr string
		wantOK  bool
	}{
		{"plain integer", "123", "123", true},
		{"leading/trailing spaces", "  42  ", "42", true},
		{"negative zero", "-0", "0", true},
		{"negative number", "-7", "-7", true},
		{"zero", "0", "0", true},
		{"leading zeros", "00", "0", true},
		{"large number", "99999999999999999999", "99999999999999999999", true},
		{"hex prefix rejected", "0x10", "", false},
		{"alpha string", "abc", "", false},
		{"empty string", "", "", false},
		{"only spaces", "   ", "", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotStr, gotOK := normalizeSignedDecimal(tc.input)
			if gotOK != tc.wantOK {
				t.Errorf("normalizeSignedDecimal(%q) ok = %v, want %v", tc.input, gotOK, tc.wantOK)
			}
			if gotStr != tc.wantStr {
				t.Errorf("normalizeSignedDecimal(%q) = %q, want %q", tc.input, gotStr, tc.wantStr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseIntString
// ---------------------------------------------------------------------------

func TestParseIntString(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		wantStr string
		wantOK  bool
	}{
		// integer types
		{"int64 positive", int64(42), "42", true},
		{"int64 negative", int64(-1), "-1", true},
		{"int64 zero", int64(0), "0", true},
		{"int32", int32(100), "100", true},
		{"int16", int16(-300), "-300", true},
		{"int8", int8(127), "127", true},
		{"int", int(999), "999", true},
		// unsigned integer types
		{"uint64", uint64(18446744073709551615), "18446744073709551615", true},
		{"uint32", uint32(0xFFFFFFFF), "4294967295", true},
		{"uint16", uint16(65535), "65535", true},
		{"uint8", uint8(255), "255", true},
		{"uint", uint(42), "42", true},
		// float64 – whole numbers
		{"float64 whole", float64(1000.0), "1000", true},
		{"float64 zero", float64(0.0), "0", true},
		{"float64 negative whole", float64(-5.0), "-5", true},
		// float64 – non-integer
		{"float64 fractional", float64(3.14), "", false},
		{"float64 NaN", float64Nan(), "", false},
		{"float64 +Inf", float64PosInf(), "", false},
		{"float64 -Inf", float64NegInf(), "", false},
		// float32
		{"float32 whole", float32(7.0), "7", true},
		{"float32 fractional", float32(1.5), "", false},
		// json.Number
		{"json.Number integer", json.Number("9999"), "9999", true},
		{"json.Number negative", json.Number("-3"), "-3", true},
		{"json.Number float string", json.Number("1.5"), "", false},
		// string
		{"string integer", "256", "256", true},
		{"string with spaces", "  10  ", "10", true},
		{"string non-integer", "not-a-number", "", false},
		{"string empty", "", "", false},
		// unsupported type
		{"bool unsupported", true, "", false},
		{"nil unsupported", nil, "", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotStr, gotOK := parseIntString(tc.input)
			if gotOK != tc.wantOK {
				t.Errorf("parseIntString(%v) ok = %v, want %v", tc.input, gotOK, tc.wantOK)
			}
			if gotStr != tc.wantStr {
				t.Errorf("parseIntString(%v) = %q, want %q", tc.input, gotStr, tc.wantStr)
			}
		})
	}
}

// helpers to produce special float64 values without importing "math" in test
// (avoids a direct math import; the values are computed at call time)
func float64Nan() float64    { var z float64; return z / z }
func float64PosInf() float64 { var z float64; return 1.0 / z }
func float64NegInf() float64 { var z float64; return -1.0 / z }

// ---------------------------------------------------------------------------
// isZeroTypeKey
// ---------------------------------------------------------------------------

func TestIsZeroTypeKey(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"0", true},
		{"00", true}, // normalizeSignedDecimal("00") == "0"
		{"-0", true},
		{"1", false},
		{"-1", false},
		{"abc", false},
		{"0x0", false}, // hex rejected by normalizeSignedDecimal
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			got := isZeroTypeKey(tc.input)
			if got != tc.want {
				t.Errorf("isZeroTypeKey(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractSourceLocation
// ---------------------------------------------------------------------------

func TestExtractSourceLocation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantFile string
		wantLine string
	}{
		{
			name:     "normal file:line",
			input:    "src/foo.c:42",
			wantFile: "src/foo.c",
			wantLine: "42",
		},
		{
			name:     "no colon",
			input:    "nocoton",
			wantFile: "nocoton",
			wantLine: "-1",
		},
		{
			name:     "empty string",
			input:    "",
			wantFile: "",
			wantLine: "-1",
		},
		{
			name:     "multiple colons uses first split",
			input:    "a:b:c",
			wantFile: "a",
			wantLine: "b",
		},
		{
			name:     "path with colon and line zero",
			input:    "dir/sub/file.c:0",
			wantFile: "dir/sub/file.c",
			wantLine: "0",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := extractSourceLocation(tc.input)
			if got.SourceFile != tc.wantFile {
				t.Errorf("extractSourceLocation(%q).SourceFile = %q, want %q", tc.input, got.SourceFile, tc.wantFile)
			}
			if got.SourceLine != tc.wantLine {
				t.Errorf("extractSourceLocation(%q).SourceLine = %q, want %q", tc.input, got.SourceLine, tc.wantLine)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// correlationCacheKey
// ---------------------------------------------------------------------------

func TestCorrelationCacheKey(t *testing.T) {
	tests := []struct {
		name    string
		fn      functionEntry
		wantKey string
	}{
		{
			name:    "no type arguments",
			fn:      functionEntry{FileLocation: "file.c:10"},
			wantKey: "file.c:10",
		},
		{
			name:    "empty type arguments",
			fn:      functionEntry{FileLocation: "file.c:10", TypeArguments: []string{}},
			wantKey: "file.c:10",
		},
		{
			name:    "single type argument",
			fn:      functionEntry{FileLocation: "file.c:10", TypeArguments: []string{"1"}},
			wantKey: "file.c:10\x1f1",
		},
		{
			name:    "multiple type arguments",
			fn:      functionEntry{FileLocation: "file.c:10", TypeArguments: []string{"1", "2", "3"}},
			wantKey: "file.c:10\x1f1,2,3",
		},
		{
			name:    "empty file location with args",
			fn:      functionEntry{FileLocation: "", TypeArguments: []string{"7"}},
			wantKey: "\x1f7",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := correlationCacheKey(tc.fn)
			if got != tc.wantKey {
				t.Errorf("correlationCacheKey(%+v) = %q, want %q", tc.fn, got, tc.wantKey)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildCorrelationPlan
// ---------------------------------------------------------------------------

func TestBuildCorrelationPlan(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		unique, mapping := buildCorrelationPlan([]functionEntry{})
		if len(unique) != 0 {
			t.Errorf("expected 0 unique functions, got %d", len(unique))
		}
		if len(mapping) != 0 {
			t.Errorf("expected empty mapping, got %v", mapping)
		}
	})

	t.Run("two identical functions deduplicated", func(t *testing.T) {
		fn := functionEntry{FileLocation: "foo.c:1", TypeArguments: []string{"10"}}
		unique, mapping := buildCorrelationPlan([]functionEntry{fn, fn})
		if len(unique) != 1 {
			t.Fatalf("expected 1 unique function, got %d", len(unique))
		}
		if len(mapping) != 2 {
			t.Fatalf("expected mapping length 2, got %d", len(mapping))
		}
		if mapping[0] != 0 || mapping[1] != 0 {
			t.Errorf("both rows should point to unique idx 0, got %v", mapping)
		}
	})

	t.Run("two different functions stay separate", func(t *testing.T) {
		fn1 := functionEntry{FileLocation: "foo.c:1", TypeArguments: []string{"10"}}
		fn2 := functionEntry{FileLocation: "bar.c:2", TypeArguments: []string{"20"}}
		unique, mapping := buildCorrelationPlan([]functionEntry{fn1, fn2})
		if len(unique) != 2 {
			t.Fatalf("expected 2 unique functions, got %d", len(unique))
		}
		if !reflect.DeepEqual(mapping, []int{0, 1}) {
			t.Errorf("expected mapping [0, 1], got %v", mapping)
		}
	})

	t.Run("mixed duplicate and unique", func(t *testing.T) {
		fn1 := functionEntry{FileLocation: "a.c:1"}
		fn2 := functionEntry{FileLocation: "b.c:2"}
		// fn1 repeated at positions 0, 1, 3; fn2 at position 2
		fns := []functionEntry{fn1, fn1, fn2, fn1}
		unique, mapping := buildCorrelationPlan(fns)
		if len(unique) != 2 {
			t.Fatalf("expected 2 unique, got %d", len(unique))
		}
		want := []int{0, 0, 1, 0}
		if !reflect.DeepEqual(mapping, want) {
			t.Errorf("mapping = %v, want %v", mapping, want)
		}
	})

	t.Run("originalRowIdx preserved in unique set", func(t *testing.T) {
		fn := functionEntry{OriginalRowIdx: 99, FileLocation: "x.c:5"}
		unique, _ := buildCorrelationPlan([]functionEntry{fn})
		if unique[0].OriginalRowIdx != 99 {
			t.Errorf("OriginalRowIdx = %d, want 99", unique[0].OriginalRowIdx)
		}
	})
}

// ---------------------------------------------------------------------------
// extractFuncSigFriendlyTypeTags
// ---------------------------------------------------------------------------

func TestExtractFuncSigFriendlyTypeTags(t *testing.T) {
	t.Run("zero key returns void", func(t *testing.T) {
		result := extractFuncSigFriendlyTypeTags("0", map[string]typeEntry{})
		if !reflect.DeepEqual(result, []string{"void"}) {
			t.Errorf("got %v, want [\"void\"]", result)
		}
	})

	t.Run("empty key returns void", func(t *testing.T) {
		result := extractFuncSigFriendlyTypeTags("", map[string]typeEntry{})
		if !reflect.DeepEqual(result, []string{"void"}) {
			t.Errorf("got %v, want [\"void\"]", result)
		}
	})

	t.Run("unknown key returns N/A", func(t *testing.T) {
		result := extractFuncSigFriendlyTypeTags("999", map[string]typeEntry{})
		if !reflect.DeepEqual(result, []string{"N/A"}) {
			t.Errorf("got %v, want [\"N/A\"]", result)
		}
	})

	t.Run("type with name stops at name tag", func(t *testing.T) {
		typeMap := map[string]typeEntry{
			"1": {Addr: "1", Tag: "DW_TAG_base_type", Name: "int"},
		}
		result := extractFuncSigFriendlyTypeTags("1", typeMap)
		want := []string{"DW_TAG_base_type", "int"}
		if !reflect.DeepEqual(result, want) {
			t.Errorf("got %v, want %v", result, want)
		}
	})

	t.Run("type with BaseTypeString stops at BaseTypeString", func(t *testing.T) {
		typeMap := map[string]typeEntry{
			"2": {Addr: "2", Tag: "DW_TAG_typedef", BaseTypeString: "unsigned int"},
		}
		result := extractFuncSigFriendlyTypeTags("2", typeMap)
		want := []string{"DW_TAG_typedef", "unsigned int"}
		if !reflect.DeepEqual(result, want) {
			t.Errorf("got %v, want %v", result, want)
		}
	})

	t.Run("follows BaseTypeAddr chain", func(t *testing.T) {
		typeMap := map[string]typeEntry{
			"10": {Addr: "10", Tag: "DW_TAG_pointer_type", BaseTypeAddr: "11"},
			"11": {Addr: "11", Tag: "DW_TAG_base_type", Name: "char"},
		}
		result := extractFuncSigFriendlyTypeTags("10", typeMap)
		want := []string{"DW_TAG_pointer_type", "DW_TAG_base_type", "char"}
		if !reflect.DeepEqual(result, want) {
			t.Errorf("got %v, want %v", result, want)
		}
	})

	t.Run("chain ending at zero key appends void", func(t *testing.T) {
		typeMap := map[string]typeEntry{
			"20": {Addr: "20", Tag: "DW_TAG_pointer_type", BaseTypeAddr: "0"},
		}
		result := extractFuncSigFriendlyTypeTags("20", typeMap)
		want := []string{"DW_TAG_pointer_type", "void"}
		if !reflect.DeepEqual(result, want) {
			t.Errorf("got %v, want %v", result, want)
		}
	})

	t.Run("cycle detection appends Infinite loop", func(t *testing.T) {
		// 30 → 31 → 30 (cycle)
		typeMap := map[string]typeEntry{
			"30": {Addr: "30", Tag: "DW_TAG_const_type", BaseTypeAddr: "31"},
			"31": {Addr: "31", Tag: "DW_TAG_volatile_type", BaseTypeAddr: "30"},
		}
		result := extractFuncSigFriendlyTypeTags("30", typeMap)
		// Must contain "Infinite loop" somewhere (exact position depends on cycle length)
		found := false
		for _, tag := range result {
			if tag == "Infinite loop" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected \"Infinite loop\" in result, got %v", result)
		}
	})

	t.Run("array tag emits size annotation", func(t *testing.T) {
		typeMap := map[string]typeEntry{
			"40": {Addr: "40", Tag: "DW_TAG_array_type", ConstSize: 8, BaseTypeAddr: "41"},
			"41": {Addr: "41", Tag: "DW_TAG_base_type", Name: "int"},
		}
		result := extractFuncSigFriendlyTypeTags("40", typeMap)
		// result must contain the ARRAY-SIZE annotation
		found := false
		for _, tag := range result {
			if tag == "ARRAY-SIZE: 8" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected \"ARRAY-SIZE: 8\" in result, got %v", result)
		}
	})
}

// ---------------------------------------------------------------------------
// convertParamListToStrV2
// ---------------------------------------------------------------------------

func TestConvertParamListToStrV2(t *testing.T) {
	tests := []struct {
		name      string
		paramList []string
		want      string
	}{
		{
			name:      "empty list",
			paramList: []string{},
			want:      "",
		},
		{
			name:      "pointer suffix",
			paramList: []string{"DW_TAG_pointer_type", "int"},
			want:      "int *",
		},
		{
			name:      "reference suffix",
			paramList: []string{"DW_TAG_reference_type", "int"},
			want:      "int &",
		},
		{
			name:      "const prefix",
			paramList: []string{"DW_TAG_const_type", "char"},
			want:      "const char",
		},
		{
			name:      "struct type",
			paramList: []string{"DW_TAG_structure_type", "MyStruct"},
			want:      "struct MyStruct",
		},
		{
			name:      "base type tag is transparent",
			paramList: []string{"DW_TAG_base_type", "int"},
			want:      "int",
		},
		{
			name:      "typedef tag is transparent",
			paramList: []string{"DW_TAG_typedef", "size_t"},
			want:      "size_t",
		},
		{
			name:      "class type tag is transparent",
			paramList: []string{"DW_TAG_class_type", "Foo"},
			want:      "Foo",
		},
		{
			name:      "enumeration type tag is transparent",
			paramList: []string{"DW_TAG_enumeration_type", "Color"},
			want:      "Color",
		},
		{
			name:      "const pointer to int",
			paramList: []string{"DW_TAG_const_type", "DW_TAG_pointer_type", "int"},
			want:      "const int *",
		},
		{
			name:      "double pointer",
			paramList: []string{"DW_TAG_pointer_type", "DW_TAG_pointer_type", "char"},
			want:      "char **",
		},
		{
			name:      "void (single void string)",
			paramList: []string{"void"},
			want:      "void",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := convertParamListToStrV2(tc.paramList)
			if got != tc.want {
				t.Errorf("convertParamListToStrV2(%v) = %q, want %q", tc.paramList, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractDebuggedFunctionSignature
// ---------------------------------------------------------------------------

func TestExtractDebuggedFunctionSignature(t *testing.T) {
	t.Run("empty TypeArguments gives N/A return and empty params", func(t *testing.T) {
		fn := functionEntry{TypeArguments: []string{}}
		sig := extractDebuggedFunctionSignature(fn, map[string]typeEntry{})
		if sig.ReturnType != "N/A" {
			t.Errorf("ReturnType = %v, want \"N/A\"", sig.ReturnType)
		}
		if len(sig.Params) != 0 {
			t.Errorf("Params = %v, want empty", sig.Params)
		}
	})

	t.Run("nil TypeArguments gives N/A return and empty params", func(t *testing.T) {
		fn := functionEntry{}
		sig := extractDebuggedFunctionSignature(fn, map[string]typeEntry{})
		if sig.ReturnType != "N/A" {
			t.Errorf("ReturnType = %v, want \"N/A\"", sig.ReturnType)
		}
		if len(sig.Params) != 0 {
			t.Errorf("Params = %v, want empty", sig.Params)
		}
	})

	t.Run("one TypeArgument means return-type-only, no params", func(t *testing.T) {
		typeMap := map[string]typeEntry{
			"1": {Addr: "1", Tag: "DW_TAG_base_type", Name: "int"},
		}
		fn := functionEntry{TypeArguments: []string{"1"}}
		sig := extractDebuggedFunctionSignature(fn, typeMap)
		wantReturn := []string{"DW_TAG_base_type", "int"}
		if !reflect.DeepEqual(sig.ReturnType, wantReturn) {
			t.Errorf("ReturnType = %v, want %v", sig.ReturnType, wantReturn)
		}
		if len(sig.Params) != 0 {
			t.Errorf("Params = %v, want empty", sig.Params)
		}
	})

	t.Run("return type is void (zero key)", func(t *testing.T) {
		fn := functionEntry{TypeArguments: []string{"0"}}
		sig := extractDebuggedFunctionSignature(fn, map[string]typeEntry{})
		wantReturn := []string{"void"}
		if !reflect.DeepEqual(sig.ReturnType, wantReturn) {
			t.Errorf("ReturnType = %v, want %v", sig.ReturnType, wantReturn)
		}
	})

	t.Run("multiple TypeArguments fill params", func(t *testing.T) {
		typeMap := map[string]typeEntry{
			"1": {Addr: "1", Tag: "DW_TAG_base_type", Name: "int"},
			"2": {Addr: "2", Tag: "DW_TAG_base_type", Name: "char"},
			"3": {Addr: "3", Tag: "DW_TAG_pointer_type", BaseTypeAddr: "2"},
		}
		// TypeArguments[0] = return type, [1], [2] = params
		fn := functionEntry{TypeArguments: []string{"1", "3", "0"}}
		sig := extractDebuggedFunctionSignature(fn, typeMap)

		wantReturn := []string{"DW_TAG_base_type", "int"}
		if !reflect.DeepEqual(sig.ReturnType, wantReturn) {
			t.Errorf("ReturnType = %v, want %v", sig.ReturnType, wantReturn)
		}
		if len(sig.Params) != 2 {
			t.Fatalf("expected 2 params, got %d", len(sig.Params))
		}
		// param 0: pointer → char
		wantP0 := []string{"DW_TAG_pointer_type", "DW_TAG_base_type", "char"}
		if !reflect.DeepEqual(sig.Params[0], wantP0) {
			t.Errorf("Params[0] = %v, want %v", sig.Params[0], wantP0)
		}
		// param 1: zero key → void
		wantP1 := []string{"void"}
		if !reflect.DeepEqual(sig.Params[1], wantP1) {
			t.Errorf("Params[1] = %v, want %v", sig.Params[1], wantP1)
		}
	})
}
