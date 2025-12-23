package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/models"
)

type Runner interface {
	Run(ctx context.Context, config *RunConfig) (*RunResult, error)
}

type RunConfig struct {
	Lockfile                       *models.Lockfile
	LockfilePath                   string
	DryRun                         bool
	KeepTemp                       bool
	RequireProvenance              bool
	ExpectedSource                 string
	Timeout                        time.Duration
	CommandOverride                string
	BinName                        string
	AllowMissingInstalledIntegrity bool
	AllowPrivateTarballHosts       bool
}

type RunResult struct {
	ExecPath           string
	Args               []string
	TempDir            string
	ExitCode           int
	ProvenanceVerified bool
	IntegrityVerified  bool

	// receipt fields
	PinnedIntegrity       string
	ComputedTarballSRI    string
	ComputedTarballSHA256 string
	InstalledIntegrity    string
	ResolvedSource        string
	ProvenanceInfo        *models.ProvenanceInfo
}

func GetRunner(artifactType models.ArtifactType) (Runner, error) {
	switch artifactType {
	case models.ArtifactTypeNPM:
		return &NPMRunner{}, nil
	case models.ArtifactTypeOCI:
		return &OCIRunner{}, nil
	case models.ArtifactTypeLocal:
		return nil, fmt.Errorf("local artifacts cannot use enforced execution (no artifact pin)")
	default:
		return nil, fmt.Errorf("unknown artifact type: %s", artifactType)
	}
}

func createSecureTempDir(prefix string) (string, error) {
	tempDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	if err := os.Chmod(tempDir, 0700); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to set temp directory permissions: %w", err)
	}

	return tempDir, nil
}

func execCommand(ctx context.Context, name string, args []string, dir string, env []string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return -1, err
	}

	return 0, nil
}

func writeMinimalPackageJSON(dir string) error {
	content := `{
  "name": "mcptrust-runner-temp",
  "version": "1.0.0",
  "private": true
}
`
	return os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0600)
}

func extractUnscopedName(name string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return name
}
