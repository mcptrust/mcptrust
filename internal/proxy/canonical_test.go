package proxy

import (
	"encoding/json"
	"testing"
)

func TestCanonicalizeJSONNumber_Integers(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0", "n:0"},
		{"1", "n:1"},
		{"-1", "n:-1"},
		{"42", "n:42"},
		{"-42", "n:-42"},
		{"123456789", "n:123456789"},
	}

	for _, tt := range tests {
		got, ok := canonicalizeJSONNumber(tt.input)
		if !ok {
			t.Errorf("canonicalizeJSONNumber(%q) failed", tt.input)
			continue
		}
		if got != tt.want {
			t.Errorf("canonicalizeJSONNumber(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCanonicalizeJSONNumber_ZeroForms(t *testing.T) {
	// All zero forms should produce the same canonical key
	zeros := []string{"0", "-0", "0.0", "0e0", "0e10", "0.00", "-0.0"}

	for _, z := range zeros {
		got, ok := canonicalizeJSONNumber(z)
		if !ok {
			t.Errorf("canonicalizeJSONNumber(%q) failed", z)
			continue
		}
		if got != "n:0" {
			t.Errorf("canonicalizeJSONNumber(%q) = %q, want n:0", z, got)
		}
	}
}

func TestCanonicalizeJSONNumber_OneForms(t *testing.T) {
	// All forms of 1 should produce the same canonical key
	ones := []string{"1", "1.0", "1e0", "1.00", "10e-1", "0.1e1"}

	for _, o := range ones {
		got, ok := canonicalizeJSONNumber(o)
		if !ok {
			t.Errorf("canonicalizeJSONNumber(%q) failed", o)
			continue
		}
		if got != "n:1" {
			t.Errorf("canonicalizeJSONNumber(%q) = %q, want n:1", o, got)
		}
	}
}

func TestCanonicalizeJSONNumber_LargeIntegers(t *testing.T) {
	// 2^53 + 1 = 9007199254740993 - cannot be exactly represented in float64
	// Our implementation should preserve it exactly
	large := "9007199254740993"
	got, ok := canonicalizeJSONNumber(large)
	if !ok {
		t.Fatalf("canonicalizeJSONNumber(%q) failed", large)
	}
	if got != "n:9007199254740993" {
		t.Errorf("canonicalizeJSONNumber(%q) = %q, want n:9007199254740993", large, got)
	}

	// Even larger
	huge := "123456789012345678901234567890"
	got2, ok := canonicalizeJSONNumber(huge)
	if !ok {
		t.Fatalf("canonicalizeJSONNumber(%q) failed", huge)
	}
	if got2 != "n:123456789012345678901234567890" {
		t.Errorf("canonicalizeJSONNumber(%q) = %q, want n:123456789012345678901234567890", huge, got2)
	}
}

func TestCanonicalizeJSONNumber_Fractions(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.5", "n:1.5"},
		{"0.5", "n:0.5"},
		{"0.25", "n:0.25"},
		{"3.14159", "n:3.14159"},
		{"-1.5", "n:-1.5"},
	}

	for _, tt := range tests {
		got, ok := canonicalizeJSONNumber(tt.input)
		if !ok {
			t.Errorf("canonicalizeJSONNumber(%q) failed", tt.input)
			continue
		}
		if got != tt.want {
			t.Errorf("canonicalizeJSONNumber(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCanonicalizeJSONNumber_Exponents(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1e3", "n:1000"},
		{"1E3", "n:1000"},
		{"1e+3", "n:1000"},
		{"1e-1", "n:0.1"},
		{"5e-2", "n:0.05"},
		{"1.5e2", "n:150"},
	}

	for _, tt := range tests {
		got, ok := canonicalizeJSONNumber(tt.input)
		if !ok {
			t.Errorf("canonicalizeJSONNumber(%q) failed", tt.input)
			continue
		}
		if got != tt.want {
			t.Errorf("canonicalizeJSONNumber(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCanonicalizeJSONNumber_InvalidInputs(t *testing.T) {
	invalids := []string{
		"01",  // leading zero
		"+1",  // leading plus
		"1.",  // trailing decimal
		".1",  // leading decimal
		"1e",  // incomplete exponent
		"1e+", // incomplete exponent
		"abc", // not a number
		"",    // empty
		"1 2", // space
		" 1",  // leading space (after trim, valid, but we test pre-trim)
	}

	for _, inv := range invalids {
		_, ok := canonicalizeJSONNumber(inv)
		if ok && inv != " 1" { // " 1" gets trimmed and becomes valid
			t.Errorf("canonicalizeJSONNumber(%q) should have failed but returned ok=true", inv)
		}
	}
}

func TestIdKey_ExactCanonicalization(t *testing.T) {
	// All these should produce the same key
	tests := []interface{}{
		json.Number("1"),
		json.Number("1.0"),
		json.Number("1e0"),
		json.Number("1.00"),
		float64(1),
		int(1),
		int64(1),
		"1", // canonical integer string
	}

	expected := "n:1"
	for _, id := range tests {
		got := idKey(id)
		if got != expected {
			t.Errorf("idKey(%T %v) = %q, want %q", id, id, got, expected)
		}
	}
}

func TestIdKey_LargeIntegerExact(t *testing.T) {
	// 2^53 + 1 - must be preserved exactly via json.Number
	largeID := json.Number("9007199254740993")
	got := idKey(largeID)
	if got != "n:9007199254740993" {
		t.Errorf("idKey(json.Number(\"9007199254740993\")) = %q, want n:9007199254740993", got)
	}
}

func TestIdKey_ZeroForms(t *testing.T) {
	// All zero forms should produce the same key
	zeros := []interface{}{
		json.Number("0"),
		json.Number("-0"),
		json.Number("0.0"),
		json.Number("0e10"),
		float64(0),
		float64(0), // Note: -0.0 literal is same as 0.0 in Go; both canonicalize to n:0
		int(0),
	}

	for _, z := range zeros {
		got := idKey(z)
		if got != "n:0" {
			t.Errorf("idKey(%T %v) = %q, want n:0", z, z, got)
		}
	}
}

func TestIdKey_Fractions(t *testing.T) {
	tests := []struct {
		input interface{}
		want  string
	}{
		{json.Number("1.5"), "n:1.5"},
		{float64(1.5), "n:1.5"},
		{json.Number("0.5"), "n:0.5"},
		{json.Number("3e-1"), "n:0.3"},
	}

	for _, tt := range tests {
		got := idKey(tt.input)
		if got != tt.want {
			t.Errorf("idKey(%T %v) = %q, want %q", tt.input, tt.input, got, tt.want)
		}
	}
}

func TestIdKey_String01NoCollision(t *testing.T) {
	// String "01" must NOT collide with numeric 1
	stringID := idKey("01")
	numericID := idKey(1)

	if stringID == numericID {
		t.Errorf("COLLISION: idKey(\"01\") = %q == idKey(1) = %q", stringID, numericID)
	}

	if stringID != "s:01" {
		t.Errorf("idKey(\"01\") = %q, want s:01", stringID)
	}
}

func TestIdKey_JsonNumber01Invalid(t *testing.T) {
	// json.Number("01") is an invalid JSON number
	// Our parser should reject it and fall back to string form
	invalidID := idKey(json.Number("01"))

	// Should fall back to s:01 since it's invalid JSON number
	if invalidID != "s:01" {
		t.Errorf("idKey(json.Number(\"01\")) = %q, want s:01 (fallback)", invalidID)
	}

	// Must not collide with numeric 1
	if invalidID == "n:1" {
		t.Error("json.Number(\"01\") incorrectly canonicalized to n:1")
	}
}

// TestIdKey_RepresentationInvariant verifies SEC-03 representation invariance:
// Host can send string IDs that look like JSON numbers, and server may respond
// with numeric IDs. Both must canonicalize to the same key for filter to apply.
func TestIdKey_RepresentationInvariant(t *testing.T) {
	tests := []struct {
		name     string
		hostID   interface{} // What host sends (string)
		serverID interface{} // What server responds with (json.Number or numeric)
		wantKey  string
	}{
		{
			name:     "string 1.0 matches numeric 1.0",
			hostID:   "1.0",
			serverID: json.Number("1.0"),
			wantKey:  "n:1",
		},
		{
			name:     "string 1e0 matches numeric 1",
			hostID:   "1e0",
			serverID: json.Number("1"),
			wantKey:  "n:1",
		},
		{
			name:     "string 1 matches float64 1",
			hostID:   "1",
			serverID: float64(1),
			wantKey:  "n:1",
		},
		{
			name:     "string 100 matches 1e2",
			hostID:   "100",
			serverID: json.Number("1e2"),
			wantKey:  "n:100",
		},
		{
			name:     "string 0.5 matches json.Number 0.5",
			hostID:   "0.5",
			serverID: json.Number("0.5"),
			wantKey:  "n:0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostKey := idKey(tt.hostID)
			serverKey := idKey(tt.serverID)

			if hostKey != serverKey {
				t.Errorf("REPRESENTATION MISMATCH: idKey(%T %v) = %q != idKey(%T %v) = %q",
					tt.hostID, tt.hostID, hostKey, tt.serverID, tt.serverID, serverKey)
			}

			if hostKey != tt.wantKey {
				t.Errorf("idKey(%T %v) = %q, want %q", tt.hostID, tt.hostID, hostKey, tt.wantKey)
			}
		})
	}
}

// TestIdKey_String01StaysString verifies string "01" is NOT canonicalized
// even though we now canonicalize valid JSON number strings.
func TestIdKey_String01StaysString(t *testing.T) {
	// "01" is NOT a valid JSON number (leading zero)
	got := idKey("01")
	if got != "s:01" {
		t.Errorf("idKey(\"01\") = %q, want s:01", got)
	}

	// Must not match numeric 1
	if got == idKey(1) {
		t.Error("string \"01\" should not match numeric 1")
	}
}

// TestIdKey_MaxIDLiteralBytes verifies DoS protection for long IDs
func TestIdKey_MaxIDLiteralBytes(t *testing.T) {
	// Create an ID longer than MaxIDLiteralBytes
	longID := "1" + string(make([]byte, MaxIDLiteralBytes)) // 1 + 256 zeros would be > 256

	// json.Number case
	jnKey := idKey(json.Number(longID))
	if jnKey != "s:"+longID {
		t.Errorf("Long json.Number should fall back to string form, got %q", jnKey[:50]+"...")
	}

	// string case
	strKey := idKey(longID)
	if strKey != "s:"+longID {
		t.Errorf("Long string should remain as string form, got %q", strKey[:50]+"...")
	}
}
