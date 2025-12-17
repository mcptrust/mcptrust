package sigstore

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// MockRunner for testing
type MockRunner struct {
	RunFunc func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error)
	Calls   []MockCall
}

type MockCall struct {
	Name string
	Args []string
	Env  []string
}

func (m *MockRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
	m.Calls = append(m.Calls, MockCall{Name: name, Args: args, Env: env})
	if m.RunFunc != nil {
		return m.RunFunc(ctx, name, args, env)
	}
	return nil, nil, nil
}

func TestSignBundle_CommandConstruction(t *testing.T) {
	mock := &MockRunner{
		RunFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
			if name == "cosign" && len(args) > 0 && args[0] == "version" {
				return []byte("cosign v2.4.1"), nil, nil
			}
			if name == "cosign" && len(args) > 0 && args[0] == "sign-blob" {
				// verify args
				hasYes := false
				hasBundle := false
				for i, arg := range args {
					if arg == "--yes" {
						hasYes = true
					}
					if arg == "--bundle" && i+1 < len(args) {
						hasBundle = true
					}
				}
				if !hasYes {
					return nil, []byte("missing --yes"), errors.New("missing --yes")
				}
				if !hasBundle {
					return nil, []byte("missing --bundle"), errors.New("missing --bundle")
				}

				// check COSIGN_YES env
				hasCosignYes := false
				for _, e := range env {
					if e == "COSIGN_YES=true" {
						hasCosignYes = true
					}
				}
				if !hasCosignYes {
					return nil, []byte("missing COSIGN_YES env"), errors.New("missing COSIGN_YES")
				}

				// simulate OIDC not available
				return nil, []byte("no identity token found"), errors.New("exit 1")
			}
			return nil, nil, nil
		},
	}

	ctx := context.Background()
	_, err := SignBundle(ctx, "/tmp/test-artifact", mock)

	// expect OIDC error (not in CI)
	if err == nil {
		t.Fatal("expected error for missing OIDC")
	}
	if !strings.Contains(err.Error(), "OIDC") {
		t.Errorf("expected OIDC error message, got: %v", err)
	}

	// verify cosign called
	if len(mock.Calls) < 2 {
		t.Fatalf("expected at least 2 calls (version + sign-blob), got %d", len(mock.Calls))
	}

	// first call: version
	if mock.Calls[0].Args[0] != "version" {
		t.Errorf("first call should be version, got: %v", mock.Calls[0].Args)
	}

	// second call: sign-blob
	signCall := mock.Calls[1]
	if signCall.Args[0] != "sign-blob" {
		t.Errorf("second call should be sign-blob, got: %v", signCall.Args)
	}
}

// TestVerifyBundle_ExactIdentity verifies exact arg list
func TestVerifyBundle_ExactIdentity(t *testing.T) {
	var capturedArgs []string

	mock := &MockRunner{
		RunFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
			if name == "cosign" && len(args) > 0 && args[0] == "version" {
				return []byte("cosign v2.4.1"), nil, nil
			}
			if name == "cosign" && len(args) > 0 && args[0] == "verify-blob" {
				capturedArgs = args
				return []byte("Verified OK"), nil, nil
			}
			return nil, nil, nil
		},
	}

	ctx := context.Background()
	result, err := VerifyBundle(ctx, "/tmp/test-artifact", []byte(`{"test":"bundle"}`),
		"https://token.actions.githubusercontent.com",
		"https://github.com/test/repo/.github/workflows/sign.yml@refs/heads/main",
		"", // No regexp
		mock)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid result")
	}

	// verify exact args
	// expected: verify-blob --bundle <path> --certificate-oidc-issuer <issuer> --certificate-identity <id> <artifact>
	hasIdentity := false
	hasIdentityRegexp := false
	hasOIDCIssuer := false
	hasBundle := false

	for i, arg := range capturedArgs {
		if arg == "--certificate-identity" && i+1 < len(capturedArgs) {
			hasIdentity = true
			if capturedArgs[i+1] != "https://github.com/test/repo/.github/workflows/sign.yml@refs/heads/main" {
				t.Errorf("wrong identity value: %s", capturedArgs[i+1])
			}
		}
		if arg == "--certificate-identity-regexp" {
			hasIdentityRegexp = true
		}
		if arg == "--certificate-oidc-issuer" && i+1 < len(capturedArgs) {
			hasOIDCIssuer = true
			if capturedArgs[i+1] != "https://token.actions.githubusercontent.com" {
				t.Errorf("wrong issuer value: %s", capturedArgs[i+1])
			}
		}
		if arg == "--bundle" {
			hasBundle = true
		}
	}

	if !hasIdentity {
		t.Error("missing --certificate-identity flag")
	}
	if hasIdentityRegexp {
		t.Error("should NOT have --certificate-identity-regexp when using exact identity")
	}
	if !hasOIDCIssuer {
		t.Error("missing --certificate-oidc-issuer flag")
	}
	if !hasBundle {
		t.Error("missing --bundle flag")
	}
}

// TestVerifyBundle_IdentityRegexpExactArgs verifies exact arg list for regexp
func TestVerifyBundle_IdentityRegexpExactArgs(t *testing.T) {
	var capturedArgs []string

	mock := &MockRunner{
		RunFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
			if name == "cosign" && len(args) > 0 && args[0] == "version" {
				return []byte("cosign v2.4.1"), nil, nil
			}
			if name == "cosign" && len(args) > 0 && args[0] == "verify-blob" {
				capturedArgs = args
				return []byte("Verified OK"), nil, nil
			}
			return nil, nil, nil
		},
	}

	ctx := context.Background()
	result, err := VerifyBundle(ctx, "/tmp/test-artifact", []byte(`{"test":"bundle"}`),
		"https://token.actions.githubusercontent.com",
		"",                                // No exact identity
		"https://github.com/test/repo/.*", // Regexp
		mock)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid result")
	}

	// verify exact args
	hasIdentity := false
	hasIdentityRegexp := false
	hasOIDCIssuer := false
	hasBundle := false

	for i, arg := range capturedArgs {
		if arg == "--certificate-identity" {
			hasIdentity = true
		}
		if arg == "--certificate-identity-regexp" && i+1 < len(capturedArgs) {
			hasIdentityRegexp = true
			if capturedArgs[i+1] != "https://github.com/test/repo/.*" {
				t.Errorf("wrong identity-regexp value: %s", capturedArgs[i+1])
			}
		}
		if arg == "--certificate-oidc-issuer" {
			hasOIDCIssuer = true
		}
		if arg == "--bundle" {
			hasBundle = true
		}
	}

	if hasIdentity {
		t.Error("should NOT have --certificate-identity when using regexp")
	}
	if !hasIdentityRegexp {
		t.Error("missing --certificate-identity-regexp flag")
	}
	if !hasOIDCIssuer {
		t.Error("missing --certificate-oidc-issuer flag")
	}
	if !hasBundle {
		t.Error("missing --bundle flag")
	}
}

func TestVerifyBundle_CommandConstruction(t *testing.T) {
	mock := &MockRunner{
		RunFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
			if name == "cosign" && len(args) > 0 && args[0] == "version" {
				return []byte("cosign v2.4.1"), nil, nil
			}
			if name == "cosign" && len(args) > 0 && args[0] == "verify-blob" {
				// required args
				hasBundle := false
				hasIssuer := false
				hasIdentity := false
				for i, arg := range args {
					if arg == "--bundle" && i+1 < len(args) {
						hasBundle = true
					}
					if arg == "--certificate-oidc-issuer" && i+1 < len(args) {
						hasIssuer = true
					}
					if arg == "--certificate-identity" && i+1 < len(args) {
						hasIdentity = true
					}
				}
				if !hasBundle || !hasIssuer || !hasIdentity {
					return nil, []byte("missing required args"), errors.New("missing args")
				}
				return []byte("Verified OK"), nil, nil
			}
			return nil, nil, nil
		},
	}

	ctx := context.Background()
	result, err := VerifyBundle(ctx, "/tmp/test-artifact", []byte(`{"test":"bundle"}`),
		"https://token.actions.githubusercontent.com",
		"https://github.com/test/repo/.github/workflows/test.yml@refs/heads/main",
		"",
		mock)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid result")
	}

	// verify cosign verify-blob called
	found := false
	for _, call := range mock.Calls {
		if len(call.Args) > 0 && call.Args[0] == "verify-blob" {
			found = true
			break
		}
	}
	if !found {
		t.Error("verify-blob was not called")
	}
}

func TestVerifyBundle_RequiresIssuer(t *testing.T) {
	mock := &MockRunner{
		RunFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
			return nil, nil, nil
		},
	}

	ctx := context.Background()
	_, err := VerifyBundle(ctx, "/tmp/test", []byte(`{}`), "", "identity", "", mock)
	if err == nil || !strings.Contains(err.Error(), "--issuer") {
		t.Errorf("expected issuer required error, got: %v", err)
	}
}

func TestVerifyBundle_RequiresIdentity(t *testing.T) {
	mock := &MockRunner{
		RunFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
			return nil, nil, nil
		},
	}

	ctx := context.Background()
	_, err := VerifyBundle(ctx, "/tmp/test", []byte(`{}`), "issuer", "", "", mock)
	if err == nil || !strings.Contains(err.Error(), "--identity") {
		t.Errorf("expected identity required error, got: %v", err)
	}
}

func TestVerifyBundle_IdentityRegexp(t *testing.T) {
	mock := &MockRunner{
		RunFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
			if name == "cosign" && len(args) > 0 && args[0] == "version" {
				return []byte("cosign v2.4.1"), nil, nil
			}
			if name == "cosign" && len(args) > 0 && args[0] == "verify-blob" {
				// check flag
				for _, arg := range args {
					if arg == "--certificate-identity-regexp" {
						return []byte("Verified OK"), nil, nil
					}
				}
				return nil, []byte("expected regexp flag"), errors.New("no regexp")
			}
			return nil, nil, nil
		},
	}

	ctx := context.Background()
	result, err := VerifyBundle(ctx, "/tmp/test", []byte(`{}`),
		"issuer", "", ".*workflow.*", mock)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid result")
	}
}

func TestBuildGitHubActionsIdentity(t *testing.T) {
	tests := []struct {
		owner    string
		repo     string
		workflow string
		ref      string
		expected string
	}{
		{
			owner:    "mcptrust",
			repo:     "mcptrust",
			workflow: "sign.yml",
			ref:      "refs/heads/main",
			expected: "https://github.com/mcptrust/mcptrust/.github/workflows/sign.yml@refs/heads/main",
		},
		{
			owner:    "myorg",
			repo:     "myapp",
			workflow: ".github/workflows/release.yml",
			ref:      "refs/tags/v1.0.0",
			expected: "https://github.com/myorg/myapp/.github/workflows/release.yml@refs/tags/v1.0.0",
		},
	}

	for _, tc := range tests {
		result := BuildGitHubActionsIdentity(tc.owner, tc.repo, tc.workflow, tc.ref)
		if result != tc.expected {
			t.Errorf("BuildGitHubActionsIdentity(%q, %q, %q, %q)\ngot:  %q\nwant: %q",
				tc.owner, tc.repo, tc.workflow, tc.ref, result, tc.expected)
		}
	}
}

func TestGitHubActionsIssuer(t *testing.T) {
	if GitHubActionsIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("unexpected issuer: %s", GitHubActionsIssuer)
	}
}

// TestIsCI_DetectsCI confirms env var detection
func TestIsCI_DetectsCI(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected bool
	}{
		{
			name:     "CI=true",
			envVars:  map[string]string{"CI": "true"},
			expected: true,
		},
		{
			name:     "CI=1",
			envVars:  map[string]string{"CI": "1"},
			expected: true,
		},
		{
			name:     "GITHUB_ACTIONS=true",
			envVars:  map[string]string{"GITHUB_ACTIONS": "true"},
			expected: true,
		},
		{
			name:     "no CI vars",
			envVars:  map[string]string{},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Save and clear relevant env vars
			oldCI := os.Getenv("CI")
			oldGHA := os.Getenv("GITHUB_ACTIONS")
			os.Unsetenv("CI")
			os.Unsetenv("GITHUB_ACTIONS")
			defer func() {
				if oldCI != "" {
					os.Setenv("CI", oldCI)
				}
				if oldGHA != "" {
					os.Setenv("GITHUB_ACTIONS", oldGHA)
				}
			}()

			// Set test env vars
			for k, v := range tc.envVars {
				os.Setenv(k, v)
			}

			result := IsCI()
			if result != tc.expected {
				t.Errorf("IsCI() = %v, want %v", result, tc.expected)
			}
		})
	}
}

// TestGetRunner_ReturnsDefaultInCI confirms default runner in CI
func TestGetRunner_ReturnsDefaultInCI(t *testing.T) {
	// Save and set CI
	oldCI := os.Getenv("CI")
	os.Setenv("CI", "true")
	defer func() {
		if oldCI != "" {
			os.Setenv("CI", oldCI)
		} else {
			os.Unsetenv("CI")
		}
	}()

	runner := GetRunner()

	// In CI, should return DefaultRunner
	if _, ok := runner.(*DefaultRunner); !ok {
		t.Errorf("GetRunner() in CI should return *DefaultRunner, got %T", runner)
	}
}
