package locker

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

func TestCanonicalizeJSONv1_GoldenTest(t *testing.T) {
	input := map[string]interface{}{
		"version":        "1.0",
		"server_command": "npx server",
		"tools": map[string]interface{}{
			"write_file": map[string]interface{}{
				"description_hash":  "sha256:abc123",
				"input_schema_hash": "sha256:def456",
				"risk_level":        "HIGH",
			},
			"read_file": map[string]interface{}{
				"description_hash":  "sha256:111222",
				"input_schema_hash": "sha256:333444",
				"risk_level":        "LOW",
			},
		},
	}

	result, err := CanonicalizeJSONv1(input)
	if err != nil {
		t.Fatalf("CanonicalizeJSONv1 failed: %v", err)
	}

	result2, err := CanonicalizeJSONv1(input)
	if err != nil {
		t.Fatalf("CanonicalizeJSONv1 second call failed: %v", err)
	}

	if string(result) != string(result2) {
		t.Errorf("v1 not deterministic:\nfirst:  %s\nsecond: %s", result, result2)
	}

	if !strings.Contains(string(result), `"read_file"`) {
		t.Errorf("expected read_file in output")
	}
	if !strings.Contains(string(result), `"write_file"`) {
		t.Errorf("expected write_file in output")
	}

	readIdx := strings.Index(string(result), `"read_file"`)
	writeIdx := strings.Index(string(result), `"write_file"`)
	if readIdx >= writeIdx {
		t.Errorf("v1 key ordering wrong: read_file should come before write_file")
	}
}

func TestCanonicalizeJSONv2_BasicObject(t *testing.T) {
	input := map[string]interface{}{
		"z": "last",
		"a": "first",
		"m": "middle",
	}

	result, err := CanonicalizeJSONv2(input)
	if err != nil {
		t.Fatalf("CanonicalizeJSONv2 failed: %v", err)
	}

	expected := `{"a":"first","m":"middle","z":"last"}`
	if string(result) != expected {
		t.Errorf("v2 basic object:\nexpected: %s\ngot:      %s", expected, result)
	}
}

func TestCanonicalizeJSONv2_Numbers(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"integer", map[string]interface{}{"n": float64(42)}, `{"n":42}`},
		{"negative", map[string]interface{}{"n": float64(-7)}, `{"n":-7}`},
		{"zero", map[string]interface{}{"n": float64(0)}, `{"n":0}`},
		{"float", map[string]interface{}{"n": float64(3.14)}, `{"n":3.14}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSONv2(tc.input)
			if err != nil {
				t.Fatalf("CanonicalizeJSONv2 failed: %v", err)
			}
			if string(result) != tc.expected {
				t.Errorf("expected: %s, got: %s", tc.expected, result)
			}
		})
	}
}

func TestCanonicalizeJSONv2_StringEscaping(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "hello", `{"s":"hello"}`},
		{"quotes", `say "hi"`, `{"s":"say \"hi\""}`},
		{"backslash", `path\to`, `{"s":"path\\to"}`},
		{"newline", "line1\nline2", `{"s":"line1\nline2"}`},
		{"tab", "col1\tcol2", `{"s":"col1\tcol2"}`},
		{"unicode", "emoji: 🎉", `{"s":"emoji: 🎉"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]interface{}{"s": tc.input}
			result, err := CanonicalizeJSONv2(input)
			if err != nil {
				t.Fatalf("CanonicalizeJSONv2 failed: %v", err)
			}
			if string(result) != tc.expected {
				t.Errorf("expected: %s, got: %s", tc.expected, result)
			}
		})
	}
}

func TestCanonicalizeJSONv2_NestedObjects(t *testing.T) {
	input := map[string]interface{}{
		"outer": map[string]interface{}{
			"z": "inner_last",
			"a": "inner_first",
		},
		"array": []interface{}{"one", "two", float64(3)},
	}

	result, err := CanonicalizeJSONv2(input)
	if err != nil {
		t.Fatalf("CanonicalizeJSONv2 failed: %v", err)
	}

	var parsed interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Errorf("result is not valid JSON: %v", err)
	}

	arrayIdx := strings.Index(string(result), `"array"`)
	outerIdx := strings.Index(string(result), `"outer"`)
	if arrayIdx >= outerIdx {
		t.Errorf("key ordering wrong: array should come before outer")
	}

	innerA := strings.Index(string(result), `"a":"inner_first"`)
	innerZ := strings.Index(string(result), `"z":"inner_last"`)
	if innerA >= innerZ {
		t.Errorf("nested key ordering wrong: a should come before z")
	}
}

func TestCanonicalizeJSON_BackwardCompatibility(t *testing.T) {
	input := map[string]interface{}{"key": "value"}

	v1Result, err := CanonicalizeJSONv1(input)
	if err != nil {
		t.Fatalf("v1 failed: %v", err)
	}

	defaultResult, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("default failed: %v", err)
	}

	if string(v1Result) != string(defaultResult) {
		t.Errorf("CanonicalizeJSON should use v1:\nv1:      %s\ndefault: %s", v1Result, defaultResult)
	}
}

func TestCanonicalizeJSONWithVersion(t *testing.T) {
	input := map[string]interface{}{"a": float64(1)}

	v1Result, err := CanonicalizeJSONWithVersion(input, CanonV1)
	if err != nil {
		t.Fatalf("v1 failed: %v", err)
	}

	v2Result, err := CanonicalizeJSONWithVersion(input, CanonV2)
	if err != nil {
		t.Fatalf("v2 failed: %v", err)
	}

	var p1, p2 interface{}
	if err := json.Unmarshal(v1Result, &p1); err != nil {
		t.Errorf("v1 result not valid JSON: %v", err)
	}
	if err := json.Unmarshal(v2Result, &p2); err != nil {
		t.Errorf("v2 result not valid JSON: %v", err)
	}

	_, err = CanonicalizeJSONWithVersion(input, "v99")
	if err == nil {
		t.Errorf("expected error for invalid version")
	}
}

func TestCompareUTF16(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int // -1 (a < b), 0 (a == b), 1 (a > b)
	}{
		{"a", "b", -1},
		{"b", "a", 1},
		{"a", "a", 0},
		{"abc", "abd", -1},
		{"abc", "ab", 1},
		{"", "a", -1},
	}

	for _, tc := range tests {
		result := compareUTF16(tc.a, tc.b)
		normalized := 0
		if result < 0 {
			normalized = -1
		} else if result > 0 {
			normalized = 1
		}
		if normalized != tc.expected {
			t.Errorf("compareUTF16(%q, %q) = %d, expected %d", tc.a, tc.b, normalized, tc.expected)
		}
	}
}

func TestJCSRejectsNaN(t *testing.T) {
	input := map[string]interface{}{"val": math.NaN()}
	_, err := CanonicalizeJSONv2(input)
	if err == nil {
		t.Error("expected error for NaN, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "NaN") {
		t.Errorf("error should mention NaN, got: %v", err)
	}
}

func TestJCSRejectsInfinity(t *testing.T) {
	input := map[string]interface{}{"val": math.Inf(1)}
	_, err := CanonicalizeJSONv2(input)
	if err == nil {
		t.Error("expected error for Infinity, got nil")
	}
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "infinity") {
		t.Errorf("error should mention infinity, got: %v", err)
	}

	input2 := map[string]interface{}{"val": math.Inf(-1)}
	_, err2 := CanonicalizeJSONv2(input2)
	if err2 == nil {
		t.Error("expected error for -Infinity, got nil")
	}
}

func TestJCSNegativeZero(t *testing.T) {
	negZero := math.Copysign(0, -1)
	input := map[string]interface{}{"n": negZero}
	result, err := CanonicalizeJSONv2(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := `{"n":0}`
	if string(result) != expected {
		t.Errorf("-0 handling: expected %s, got %s", expected, result)
	}
}

func TestJCSAstralPlane(t *testing.T) {
	input := map[string]interface{}{
		"🎉":  "party",
		"a":  "first",
		"z":  "last",
		"ab": "second",
	}

	result, err := CanonicalizeJSONv2(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Errorf("result is not valid JSON: %v", err)
	}

	resultStr := string(result)
	aIdx := strings.Index(resultStr, `"a":`)
	abIdx := strings.Index(resultStr, `"ab":`)
	zIdx := strings.Index(resultStr, `"z":`)
	emojiIdx := strings.Index(resultStr, `"🎉":`)

	if aIdx >= abIdx || abIdx >= zIdx || zIdx >= emojiIdx {
		t.Errorf("incorrect UTF-16 ordering: got %s", resultStr)
	}
}

func TestJCSGoldenVectors(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "key_ordering",
			input:    map[string]interface{}{"b": "2", "a": "1"},
			expected: `{"a":"1","b":"2"}`,
		},
		{
			name:     "integer",
			input:    map[string]interface{}{"n": float64(42)},
			expected: `{"n":42}`,
		},
		{
			name:     "negative_integer",
			input:    map[string]interface{}{"n": float64(-17)},
			expected: `{"n":-17}`,
		},
		{
			name:     "decimal",
			input:    map[string]interface{}{"n": float64(3.14159)},
			expected: `{"n":3.14159}`,
		},
		{
			name:     "empty_object",
			input:    map[string]interface{}{},
			expected: `{}`,
		},
		{
			name:     "empty_array",
			input:    map[string]interface{}{"arr": []interface{}{}},
			expected: `{"arr":[]}`,
		},
		{
			name: "nested",
			input: map[string]interface{}{
				"b": map[string]interface{}{"z": "last", "a": "first"},
				"a": "top",
			},
			expected: `{"a":"top","b":{"a":"first","z":"last"}}`,
		},
		{
			name:     "booleans",
			input:    map[string]interface{}{"t": true, "f": false},
			expected: `{"f":false,"t":true}`,
		},
		{
			name:     "null_value",
			input:    map[string]interface{}{"n": nil},
			expected: `{"n":null}`,
		},
		{
			name:     "control_chars",
			input:    map[string]interface{}{"s": "line1\nline2\ttab"},
			expected: `{"s":"line1\nline2\ttab"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSONv2(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(result) != tc.expected {
				t.Errorf("expected: %s\ngot:      %s", tc.expected, result)
			}
		})
	}
}

func TestJCSV1V2Determinism(t *testing.T) {
	input := map[string]interface{}{
		"tools": map[string]interface{}{
			"zeta":  map[string]interface{}{"hash": "abc"},
			"alpha": map[string]interface{}{"hash": "xyz"},
		},
		"version": "1.0",
	}

	v1Results := make([]string, 5)
	for i := 0; i < 5; i++ {
		res, err := CanonicalizeJSONv1(input)
		if err != nil {
			t.Fatalf("v1 iteration %d failed: %v", i, err)
		}
		v1Results[i] = string(res)
	}
	for i := 1; i < 5; i++ {
		if v1Results[0] != v1Results[i] {
			t.Errorf("v1 not deterministic: iteration 0 != iteration %d", i)
		}
	}

	v2Results := make([]string, 5)
	for i := 0; i < 5; i++ {
		res, err := CanonicalizeJSONv2(input)
		if err != nil {
			t.Fatalf("v2 iteration %d failed: %v", i, err)
		}
		v2Results[i] = string(res)
	}
	for i := 1; i < 5; i++ {
		if v2Results[0] != v2Results[i] {
			t.Errorf("v2 not deterministic: iteration 0 != iteration %d", i)
		}
	}
}

func TestCanonVectors(t *testing.T) {
	inputPath := "../../testdata/canon_vectors/input.json"
	v1Path := "../../testdata/canon_vectors/canon_v1.json"
	v2Path := "../../testdata/canon_vectors/canon_v2.json"

	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		t.Skipf("test vectors not found: %v", err)
	}

	var input interface{}
	dec := json.NewDecoder(bytes.NewReader(inputData))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		t.Fatalf("parse input: %v", err)
	}

	v1Expected, err := os.ReadFile(v1Path)
	if err != nil {
		t.Fatalf("read v1 vector: %v", err)
	}
	v1Expected = bytes.TrimSpace(v1Expected)

	v1Result, err := CanonicalizeJSONv1(input)
	if err != nil {
		t.Fatalf("v1 canonicalize: %v", err)
	}
	if !bytes.Equal(v1Result, v1Expected) {
		t.Errorf("v1 mismatch:\nexpected: %s\ngot:      %s", v1Expected, v1Result)
	}

	v2Expected, err := os.ReadFile(v2Path)
	if err != nil {
		t.Fatalf("read v2 vector: %v", err)
	}
	v2Expected = bytes.TrimSpace(v2Expected)

	v2Result, err := CanonicalizeJSONv2(input)
	if err != nil {
		t.Fatalf("v2 canonicalize: %v", err)
	}
	if !bytes.Equal(v2Result, v2Expected) {
		t.Errorf("v2 mismatch:\nexpected: %s\ngot:      %s", v2Expected, v2Result)
	}
}
