package main

import (
	"math"
	"testing"
)

func TestParsePyYAMLScalarBoolTokens(t *testing.T) {
	cases := []struct {
		input string
		want  any
	}{
		{"NO", false},
		{"off", false},
		{"YES", true},
	}
	for _, tc := range cases {
		got, ok := parsePyYAMLScalar(tc.input)
		if !ok {
			t.Fatalf("expected token %q to parse", tc.input)
		}
		if got != tc.want {
			t.Fatalf("token %q parsed to %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParsePyYAMLScalarKeepsQuotedLikeStrings(t *testing.T) {
	cases := []string{"_1", "null"}
	for _, input := range cases {
		if got, ok := parsePyYAMLScalar(input); ok {
			t.Fatalf("expected %q to remain string, got parsed value %v", input, got)
		}
	}
}

func TestParsePyYAMLScalarIntegerParity(t *testing.T) {
	cases := []struct {
		input string
		want  any
	}{
		{"010", int64(8)},
		{"0b10", int64(2)},
		{"0x10", int64(16)},
		{"18446744073709551615", uint64(math.MaxUint64)},
	}
	for _, tc := range cases {
		got, ok := parsePyYAMLScalar(tc.input)
		if !ok {
			t.Fatalf("expected token %q to parse", tc.input)
		}
		if got != tc.want {
			t.Fatalf("token %q parsed to %v, want %v", tc.input, got, tc.want)
		}
	}

	if got, ok := parsePyYAMLScalar("09"); ok {
		t.Fatalf("expected 09 to remain string, got parsed value %v", got)
	}
}
