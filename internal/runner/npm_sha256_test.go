package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeTarballSHA256(t *testing.T) {
	// Create temp file with known content
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.tgz")
	content := []byte("test tarball content for sha256")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := ComputeTarballSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeTarballSHA256 failed: %v", err)
	}

	// Pre-computed: echo -n "test tarball content for sha256" | sha256sum
	expected := "546ca31b16fd729f0d23eee9705a087558308bddc063502229dc2f5b2b9187db"
	if hash != expected {
		t.Errorf("hash mismatch:\n  got:      %s\n  expected: %s", hash, expected)
	}
}

func TestComputeTarballSHA256_FileNotFound(t *testing.T) {
	_, err := ComputeTarballSHA256("/nonexistent/path/file.tgz")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestNormalizeSHA256(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain hex lowercase", "abc123def456", "abc123def456"},
		{"plain hex uppercase", "ABC123DEF456", "abc123def456"},
		{"with sha256 prefix", "sha256:abc123def456", "abc123def456"},
		{"with SHA256 prefix uppercase", "SHA256:ABC123DEF456", "abc123def456"},
		{"with whitespace", "  sha256:abc123  ", "abc123"},
		{"empty string", "", ""},
		{"whitespace only", "   ", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeSHA256(tc.input)
			if result != tc.expected {
				t.Errorf("NormalizeSHA256(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestVerifySHA256Match(t *testing.T) {
	tests := []struct {
		name      string
		expected  string
		actual    string
		wantError bool
	}{
		{"exact match", "abc123", "abc123", false},
		{"case difference", "ABC123", "abc123", false},
		{"prefix difference", "sha256:abc123", "abc123", false},
		{"both have prefix", "sha256:abc123", "sha256:ABC123", false},
		{"mismatch", "abc123", "def456", true},
		{"mismatch with prefix", "sha256:abc123", "sha256:def456", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySHA256Match(tc.expected, tc.actual, "test context")
			if tc.wantError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifySHA256MatchErrorMessage(t *testing.T) {
	err := VerifySHA256Match("abc123", "def456", "pinned vs computed")
	if err == nil {
		t.Fatal("expected error")
	}

	errStr := err.Error()
	if !contains(errStr, "sha256 mismatch") {
		t.Errorf("error should contain 'sha256 mismatch': %s", errStr)
	}
	if !contains(errStr, "pinned vs computed") {
		t.Errorf("error should contain context: %s", errStr)
	}
	if !contains(errStr, "abc123") {
		t.Errorf("error should contain expected hash: %s", errStr)
	}
	if !contains(errStr, "def456") {
		t.Errorf("error should contain actual hash: %s", errStr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
