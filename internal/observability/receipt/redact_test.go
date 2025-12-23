package receipt

import (
	"testing"
)

func TestRedactArgs_SensitiveFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantArgs []string
		wantFlag bool
	}{
		{
			name:     "token flag with space",
			args:     []string{"--token", "sk-secret123"},
			wantArgs: []string{"--token", "[REDACTED]"},
			wantFlag: true,
		},
		{
			name:     "token flag with equals",
			args:     []string{"--token=sk-secret123"},
			wantArgs: []string{"--token=[REDACTED]"},
			wantFlag: true,
		},
		{
			name:     "password flag",
			args:     []string{"--password", "mysecret"},
			wantArgs: []string{"--password", "[REDACTED]"},
			wantFlag: true,
		},
		{
			name:     "api-key flag",
			args:     []string{"--api-key=AIzaSyAbc123"},
			wantArgs: []string{"--api-key=[REDACTED]"},
			wantFlag: true,
		},
		{
			name:     "single dash flag",
			args:     []string{"-token", "secret"},
			wantArgs: []string{"-token", "[REDACTED]"},
			wantFlag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, wasRedacted := RedactArgs(tt.args)
			if wasRedacted != tt.wantFlag {
				t.Errorf("wasRedacted = %v, want %v", wasRedacted, tt.wantFlag)
			}
			if len(got) != len(tt.wantArgs) {
				t.Fatalf("got %d args, want %d", len(got), len(tt.wantArgs))
			}
			for i := range got {
				if got[i] != tt.wantArgs[i] {
					t.Errorf("arg[%d] = %q, want %q", i, got[i], tt.wantArgs[i])
				}
			}
		})
	}
}

func TestRedactArgs_PatternMatching(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantArgs []string
		wantFlag bool
	}{
		{
			name:     "GitHub PAT",
			args:     []string{"ghp_1234567890abcdefghij"},
			wantArgs: []string{"[REDACTED]"},
			wantFlag: true,
		},
		{
			name:     "GitHub fine-grained PAT",
			args:     []string{"github_pat_1234567890abcdefghij"},
			wantArgs: []string{"[REDACTED]"},
			wantFlag: true,
		},
		{
			name:     "OpenAI key",
			args:     []string{"sk-proj-1234567890abcdefghij"},
			wantArgs: []string{"[REDACTED]"},
			wantFlag: true,
		},
		{
			name:     "AWS access key",
			args:     []string{"AKIAIOSFODNN7EXAMPLE"},
			wantArgs: []string{"[REDACTED]"},
			wantFlag: true,
		},
		{
			name:     "Slack bot token",
			args:     []string{"xoxb-123456789-123456789-abcdefghij"},
			wantArgs: []string{"[REDACTED]"},
			wantFlag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, wasRedacted := RedactArgs(tt.args)
			if wasRedacted != tt.wantFlag {
				t.Errorf("wasRedacted = %v, want %v", wasRedacted, tt.wantFlag)
			}
			for i := range got {
				if got[i] != tt.wantArgs[i] {
					t.Errorf("arg[%d] = %q, want %q", i, got[i], tt.wantArgs[i])
				}
			}
		})
	}
}

func TestRedactArgs_JWTLike(t *testing.T) {
	// JWT-like pattern: xxx.yyy.zzz with base64-ish parts
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	args := []string{jwt}
	got, wasRedacted := RedactArgs(args)

	if !wasRedacted {
		t.Error("JWT-like string should be redacted")
	}
	if got[0] != "[REDACTED]" {
		t.Errorf("got %q, want [REDACTED]", got[0])
	}
}

func TestRedactArgs_NonSensitive(t *testing.T) {
	args := []string{
		"--output", "mcp-lock.json",
		"--timeout", "30s",
		"--v3",
		"npx", "-y", "@modelcontextprotocol/server-filesystem",
		"/tmp",
	}

	got, wasRedacted := RedactArgs(args)

	if wasRedacted {
		t.Error("non-sensitive args should not be marked as redacted")
	}

	// All args should be unchanged
	for i := range args {
		if got[i] != args[i] {
			t.Errorf("arg[%d] = %q, want %q (should be unchanged)", i, got[i], args[i])
		}
	}
}

func TestRedactArgs_MixedArgs(t *testing.T) {
	args := []string{
		"--output", "mcp-lock.json",
		"--token", "sk-secret123",
		"--v3",
	}

	got, wasRedacted := RedactArgs(args)

	if !wasRedacted {
		t.Error("mixed args with token should be redacted")
	}

	expected := []string{
		"--output", "mcp-lock.json",
		"--token", "[REDACTED]",
		"--v3",
	}

	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("arg[%d] = %q, want %q", i, got[i], expected[i])
		}
	}
}

func TestRedactArgs_EmptyArgs(t *testing.T) {
	got, wasRedacted := RedactArgs(nil)
	if wasRedacted {
		t.Error("empty args should not be marked as redacted")
	}
	if got != nil {
		t.Error("empty args should return nil")
	}

	got2, wasRedacted2 := RedactArgs([]string{})
	if wasRedacted2 {
		t.Error("empty slice should not be marked as redacted")
	}
	if len(got2) != 0 {
		t.Error("empty slice should return empty")
	}
}

func TestRedactArgs_LongSecretLike(t *testing.T) {
	// Long hex-like string that looks like a secret
	longSecret := "abcdef0123456789abcdef0123456789abcdef01"
	args := []string{longSecret}

	got, wasRedacted := RedactArgs(args)

	if !wasRedacted {
		t.Error("long secret-like string should be redacted")
	}
	if got[0] != "[REDACTED]" {
		t.Errorf("got %q, want [REDACTED]", got[0])
	}
}

func TestRedactArgs_PathsNotRedacted(t *testing.T) {
	// Paths should not be redacted even if they're long
	args := []string{
		"/very/long/path/to/some/file/that/is/definitely/more/than/32/characters.json",
		"https://example.com/api/v1/resource?query=value",
	}

	got, wasRedacted := RedactArgs(args)

	if wasRedacted {
		t.Error("paths/URLs should not be redacted")
	}
	for i := range args {
		if got[i] != args[i] {
			t.Errorf("arg[%d] = %q should be unchanged", i, got[i])
		}
	}
}
