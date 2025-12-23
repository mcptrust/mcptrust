package sigstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CommandRunner interface
type CommandRunner interface {
	Run(ctx context.Context, name string, args []string, env []string) (stdout, stderr []byte, err error)
}

// DefaultRunner captures output
type DefaultRunner struct{}

func (r *DefaultRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// InteractiveRunner for prompts
type InteractiveRunner struct{}

func (r *InteractiveRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	// No captured output in interactive mode
	return nil, nil, err
}

// IsCI detector
func IsCI() bool {
	// CI=true is set by GitHub Actions, GitLab CI, Travis, CircleCI, etc.
	if os.Getenv("CI") == "true" || os.Getenv("CI") == "1" {
		return true
	}
	// GitHub Actions also sets GITHUB_ACTIONS
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return true
	}
	return false
}

// IsInteractive check
func IsInteractive() bool {
	if IsCI() {
		return false
	}
	// Check if stdout is a TTY
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// GetRunner factory
func GetRunner() CommandRunner {
	if IsInteractive() {
		return &InteractiveRunner{}
	}
	return &DefaultRunner{}
}

// VerifyResult struct
type VerifyResult struct {
	Valid    bool
	Issuer   string
	Identity string
	Message  string
}

// SignBundle cosign sign-blob
func SignBundle(ctx context.Context, artifactPath string, runner CommandRunner) ([]byte, error) {
	if runner == nil {
		runner = &DefaultRunner{}
	}

	// check cosign
	if err := checkCosignExists(ctx, runner); err != nil {
		return nil, err
	}

	// temp file for bundle
	bundleFile, err := os.CreateTemp("", "mcptrust-bundle-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp bundle file: %w", err)
	}
	bundlePath := bundleFile.Name()
	bundleFile.Close()
	defer os.Remove(bundlePath)

	// cosign sign-blob --yes --bundle <bundlefile> <artifact>
	args := []string{
		"sign-blob",
		"--yes",
		"--bundle", bundlePath,
		artifactPath,
	}

	env := []string{"COSIGN_YES=true"}

	_, stderr, err := runner.Run(ctx, "cosign", args, env)
	if err != nil {
		stderrStr := strings.TrimSpace(string(stderr))
		if strings.Contains(stderrStr, "no identity token") ||
			strings.Contains(stderrStr, "OIDC") ||
			strings.Contains(stderrStr, "ambient credentials") {
			return nil, fmt.Errorf("keyless signing requires OIDC login (interactive) or CI OIDC token (GitHub Actions). Error: %s", stderrStr)
		}
		return nil, fmt.Errorf("cosign sign-blob failed: %w\nstderr: %s", err, stderrStr)
	}

	// Read bundle
	bundleJSON, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle file: %w", err)
	}

	if len(bundleJSON) == 0 {
		return nil, fmt.Errorf("cosign produced empty bundle")
	}

	return bundleJSON, nil
}

// VerifyBundle cosign verify-blob
func VerifyBundle(ctx context.Context, artifactPath string, bundleJSON []byte, issuer, identity, identityRegexp string, runner CommandRunner) (*VerifyResult, error) {
	if runner == nil {
		runner = &DefaultRunner{}
	}

	// check cosign
	if err := checkCosignExists(ctx, runner); err != nil {
		return nil, err
	}

	// Validate required params
	if issuer == "" {
		return nil, fmt.Errorf("--issuer is required for Sigstore verification")
	}
	if identity == "" && identityRegexp == "" {
		return nil, fmt.Errorf("--identity or --identity-regexp is required for Sigstore verification")
	}

	// write bundle to temp
	bundleFile, err := os.CreateTemp("", "mcptrust-bundle-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp bundle file: %w", err)
	}
	bundlePath := bundleFile.Name()
	defer os.Remove(bundlePath)

	if _, err := bundleFile.Write(bundleJSON); err != nil {
		bundleFile.Close()
		return nil, fmt.Errorf("failed to write bundle file: %w", err)
	}
	bundleFile.Close()

	// cosign verify-blob --bundle <bundlefile> --certificate-oidc-issuer <issuer> --certificate-identity[-regexp] <id> <artifact>
	args := []string{
		"verify-blob",
		"--bundle", bundlePath,
		"--certificate-oidc-issuer", issuer,
	}

	if identityRegexp != "" {
		args = append(args, "--certificate-identity-regexp", identityRegexp)
	} else {
		args = append(args, "--certificate-identity", identity)
	}

	args = append(args, artifactPath)

	stdout, stderr, err := runner.Run(ctx, "cosign", args, nil)
	if err != nil {
		stderrStr := strings.TrimSpace(string(stderr))
		stdoutStr := strings.TrimSpace(string(stdout))

		// Verification failed (identity/issuer mismatch)
		return &VerifyResult{
			Valid:   false,
			Issuer:  issuer,
			Message: fmt.Sprintf("verification failed: %s %s", stdoutStr, stderrStr),
		}, nil
	}

	return &VerifyResult{
		Valid:    true,
		Issuer:   issuer,
		Identity: identity,
		Message:  "Verified OK",
	}, nil
}

// checkCosignExists check
func checkCosignExists(ctx context.Context, runner CommandRunner) error {
	_, _, err := runner.Run(ctx, "cosign", []string{"version"}, nil)
	if err != nil {
		// Check if it's a "not found" error
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return fmt.Errorf("cosign not found in PATH. Install: https://docs.sigstore.dev/cosign/installation/")
		}
		// Could be permission issue or something else, but cosign exists
		return nil
	}
	return nil
}

// GitHubActionsIssuer URL
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// BuildGitHubActionsIdentity helper
func BuildGitHubActionsIdentity(owner, repo, workflowFile, ref string) string {
	// Format: https://github.com/<OWNER>/<REPO>/.github/workflows/<WORKFLOW_FILE>@<REF>
	workflowPath := workflowFile
	if !strings.HasPrefix(workflowPath, ".github/workflows/") {
		workflowPath = filepath.Join(".github/workflows", workflowFile)
	}
	return fmt.Sprintf("https://github.com/%s/%s/%s@%s", owner, repo, workflowPath, ref)
}
