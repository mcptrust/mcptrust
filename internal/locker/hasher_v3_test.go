package locker

import (
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

// TestHashNormalizedStringNormalization tests line ending normalization
func TestHashNormalizedStringNormalization(t *testing.T) {
	tests := []struct {
		name   string
		inputs []string // all should produce same hash
	}{
		{
			name: "line_endings",
			inputs: []string{
				"line1\nline2",
				"line1\r\nline2",
				"line1\rline2",
			},
		},
		{
			name: "trailing_whitespace",
			inputs: []string{
				"hello world",
				"hello world  ",
				"hello world\t",
			},
		},
		{
			name: "multiline_trailing",
			inputs: []string{
				"line1\nline2\nline3",
				"line1  \nline2\t\nline3  ",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.inputs) < 2 {
				t.Skip("need at least 2 inputs")
			}

			firstHash := HashNormalizedString(tc.inputs[0])
			for i, input := range tc.inputs[1:] {
				hash := HashNormalizedString(input)
				if hash != firstHash {
					t.Errorf("input[%d] hash differs:\nfirst: %s\ngot:   %s", i+1, firstHash, hash)
				}
			}
		})
	}
}

// TestHashJCSJSONDeterminism tests that key order doesn't affect hash
func TestHashJCSJSONDeterminism(t *testing.T) {
	// Same logical object, different construction order
	obj1 := map[string]interface{}{
		"z": "last",
		"a": "first",
		"m": "middle",
	}

	obj2 := map[string]interface{}{
		"a": "first",
		"m": "middle",
		"z": "last",
	}

	hash1, err := HashJCSJSON(obj1)
	if err != nil {
		t.Fatalf("hash1 failed: %v", err)
	}

	hash2, err := HashJCSJSON(obj2)
	if err != nil {
		t.Fatalf("hash2 failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("determinism failed:\nhash1: %s\nhash2: %s", hash1, hash2)
	}
}

// TestHashPromptArgumentsEmpty tests empty/nil arguments produce same hash
func TestHashPromptArgumentsEmpty(t *testing.T) {
	// nil args
	hash1, err := HashPromptArguments(nil)
	if err != nil {
		t.Fatalf("nil args failed: %v", err)
	}

	// empty slice
	hash2, err := HashPromptArguments([]models.PromptArgument{})
	if err != nil {
		t.Fatalf("empty slice failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("nil vs empty hash differs:\nnil:   %s\nempty: %s", hash1, hash2)
	}

	// hash should not be empty
	if hash1 == "" {
		t.Error("expected non-empty hash for empty arguments")
	}
}

// TestHashPromptArgumentsSorted tests argument order doesn't affect hash
func TestHashPromptArgumentsSorted(t *testing.T) {
	args1 := []models.PromptArgument{
		{Name: "zulu", Required: true},
		{Name: "alpha", Required: false},
	}

	args2 := []models.PromptArgument{
		{Name: "alpha", Required: false},
		{Name: "zulu", Required: true},
	}

	hash1, err := HashPromptArguments(args1)
	if err != nil {
		t.Fatalf("args1 failed: %v", err)
	}

	hash2, err := HashPromptArguments(args2)
	if err != nil {
		t.Fatalf("args2 failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("argument order affected hash:\nargs1: %s\nargs2: %s", hash1, hash2)
	}
}

// TestHashTemplateDeterminism tests template hash is stable
func TestHashTemplateDeterminism(t *testing.T) {
	hash1, err := HashTemplate("file:///{path}", "application/octet-stream")
	if err != nil {
		t.Fatalf("hash1 failed: %v", err)
	}

	hash2, err := HashTemplate("file:///{path}", "application/octet-stream")
	if err != nil {
		t.Fatalf("hash2 failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("template hash not deterministic:\nhash1: %s\nhash2: %s", hash1, hash2)
	}

	// Different mimeType should produce different hash
	hash3, err := HashTemplate("file:///{path}", "text/plain")
	if err != nil {
		t.Fatalf("hash3 failed: %v", err)
	}

	if hash1 == hash3 {
		t.Error("different mimeType should produce different hash")
	}
}

// TestHashTemplateWithoutMimeType tests optional mimeType handling
func TestHashTemplateWithoutMimeType(t *testing.T) {
	// Empty mimeType should not include it in hash
	hash1, err := HashTemplate("file:///{path}", "")
	if err != nil {
		t.Fatalf("hash1 failed: %v", err)
	}

	// Should be consistent
	hash2, err := HashTemplate("file:///{path}", "")
	if err != nil {
		t.Fatalf("hash2 failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("empty mimeType not deterministic:\nhash1: %s\nhash2: %s", hash1, hash2)
	}

	// With mimeType should be different
	hash3, err := HashTemplate("file:///{path}", "text/plain")
	if err != nil {
		t.Fatalf("hash3 failed: %v", err)
	}

	if hash1 == hash3 {
		t.Error("hash with mimeType should differ from hash without")
	}
}

// TestHashJCSJSONStability runs multiple iterations to verify stability
func TestHashJCSJSONStability(t *testing.T) {
	// Use only strings/bools/arrays/objects (no floats per safety guardrail)
	obj := map[string]interface{}{
		"nested": map[string]interface{}{
			"c": "three",
			"a": "one",
			"b": "two",
		},
		"array": []interface{}{"x", "y", "z"},
		"bool":  true,
		"null":  nil,
	}

	var firstHash string
	for i := 0; i < 10; i++ {
		hash, err := HashJCSJSON(obj)
		if err != nil {
			t.Fatalf("iteration %d failed: %v", i, err)
		}
		if i == 0 {
			firstHash = hash
		} else if hash != firstHash {
			t.Errorf("iteration %d produced different hash:\nfirst: %s\ngot:   %s", i, firstHash, hash)
		}
	}
}

// TestHashJCSJSONRejectsFloats verifies the float rejection guardrail
func TestHashJCSJSONRejectsFloats(t *testing.T) {
	obj := map[string]interface{}{
		"count": float64(42),
	}

	_, err := HashJCSJSON(obj)
	if err == nil {
		t.Error("expected error for float64 value")
	}
}

// TestHashFormat verifies sha256: prefix
func TestHashFormat(t *testing.T) {
	hash := HashNormalizedString("test")
	if len(hash) < 8 {
		t.Errorf("hash too short: %s", hash)
	}
	if hash[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix, got: %s", hash[:7])
	}

	jsonHash, err := HashJCSJSON(map[string]interface{}{"key": "value"})
	if err != nil {
		t.Fatalf("json hash failed: %v", err)
	}
	if jsonHash[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix for JSON, got: %s", jsonHash[:7])
	}
}
