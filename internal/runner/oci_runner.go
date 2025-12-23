package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mcptrust/mcptrust/internal/models"
)

// OCIRunner executor
type OCIRunner struct{}

// Run container
func (r *OCIRunner) Run(ctx context.Context, config *RunConfig) (*RunResult, error) {
	lockfile := config.Lockfile
	pin := lockfile.Artifact

	if pin == nil {
		return nil, fmt.Errorf("lockfile has no artifact pin; run 'mcptrust lock --pin' first")
	}

	if pin.Type != models.ArtifactTypeOCI {
		return nil, fmt.Errorf("artifact type %q is not OCI", pin.Type)
	}

	// Require digest for OCI images
	if pin.Digest == "" {
		return nil, fmt.Errorf("OCI artifact has no digest; digest pinning required for enforced execution")
	}

	if !strings.HasPrefix(pin.Digest, "sha256:") {
		return nil, fmt.Errorf("OCI digest must be sha256 format, got: %s", pin.Digest)
	}

	result := &RunResult{
		ExitCode: -1,
	}

	// Check for docker installation
	if !r.isDockerAvailable(ctx) {
		return nil, fmt.Errorf("docker is not installed or not in PATH")
	}

	// Verify provenance first
	if config.RequireProvenance {
		if err := r.verifyProvenance(ctx, pin, config.ExpectedSource); err != nil {
			return nil, fmt.Errorf("provenance verification failed: %w", err)
		}
		result.ProvenanceVerified = true
	}
	result.IntegrityVerified = true // Digest pinning = integrity

	// Build image ref
	pinnedImage := r.buildPinnedImageRef(pin)

	// Parse and transform the docker run command
	serverCmd := lockfile.ServerCommand
	if config.CommandOverride != "" {
		serverCmd = config.CommandOverride
	}

	execArgs, err := r.buildDockerArgs(serverCmd, pinnedImage)
	if err != nil {
		return nil, fmt.Errorf("failed to build docker arguments: %w", err)
	}

	result.ExecPath = "docker"
	result.Args = execArgs

	// In dry-run mode, we're done
	if config.DryRun {
		fmt.Printf("✓ Digest verified (pinned to %s)\n", pin.Digest[:16]+"...")
		if result.ProvenanceVerified {
			// OCI provenance via cosign is always SLSA
			fmt.Printf("✓ SLSA provenance verified (cosign)\n")
		}
		fmt.Printf("✓ Would execute: docker %s\n", strings.Join(execArgs, " "))
		result.ExitCode = 0
		return result, nil
	}

	// Execute docker run
	exitCode, err := execCommand(ctx, "docker", execArgs, "", nil)
	if err != nil {
		return nil, fmt.Errorf("docker execution failed: %w", err)
	}
	result.ExitCode = exitCode

	return result, nil
}

// isDockerAvailable checks if docker is installed
func (r *OCIRunner) isDockerAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "version")
	return cmd.Run() == nil
}

// buildPinnedImageRef
func (r *OCIRunner) buildPinnedImageRef(pin *models.ArtifactPin) string {
	// If image already contains @, use as-is
	if strings.Contains(pin.Image, "@") {
		return pin.Image
	}

	// Remove any tag and add digest
	image := pin.Image
	if colonIdx := strings.LastIndex(image, ":"); colonIdx != -1 {
		// Check it's not a port
		if slashIdx := strings.LastIndex(image, "/"); slashIdx == -1 || colonIdx > slashIdx {
			image = image[:colonIdx]
		}
	}

	return fmt.Sprintf("%s@%s", image, pin.Digest)
}

// buildDockerArgs injects pinned image into command.
// Uses strict parser for safety.
func (r *OCIRunner) buildDockerArgs(serverCmd, pinnedImage string) ([]string, error) {
	args, err := ParseServerCommand(serverCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server command: %w", err)
	}

	// Use the strict docker parser
	parsed, err := ParseDockerRunCommand(args)
	if err != nil {
		return nil, fmt.Errorf("unsupported docker command: %w", err)
	}

	// Replace image with pinned reference
	return parsed.ReplaceImage(pinnedImage), nil
}

// verifyProvenance SLSA check
func (r *OCIRunner) verifyProvenance(ctx context.Context, pin *models.ArtifactPin, expectedSource string) error {
	// Check if cosign is available
	if !r.isCosignAvailable(ctx) {
		return fmt.Errorf("cosign is required for OCI provenance verification (install from https://docs.sigstore.dev/cosign/installation/)")
	}

	// Build image reference with digest
	imageRef := r.buildPinnedImageRef(pin)

	// Build cosign verify-attestation command
	args := []string{
		"verify-attestation",
		"--type", "slsaprovenance",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
	}

	if expectedSource != "" {
		args = append(args, "--certificate-identity-regexp", expectedSource+".*")
	} else {
		args = append(args, "--certificate-identity-regexp", ".*")
	}

	args = append(args, imageRef)

	cmd := exec.CommandContext(ctx, "cosign", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign verify-attestation failed: %s %s", stdout.String(), stderr.String())
	}

	// Parse output to verify we got a valid SLSA provenance statement
	if err := r.validateProvenanceOutput(stdout.Bytes()); err != nil {
		return err
	}

	return nil
}

// isCosignAvailable checks if cosign is installed
func (r *OCIRunner) isCosignAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "cosign", "version")
	return cmd.Run() == nil
}

// validateProvenanceOutput check
func (r *OCIRunner) validateProvenanceOutput(output []byte) error {
	if len(output) == 0 {
		return fmt.Errorf("no attestation output from cosign")
	}

	// cosign outputs JSON lines, each line is an attestation
	lines := bytes.Split(output, []byte("\n"))
	foundProvenance := false

	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var attestation struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
		}

		if err := json.Unmarshal(line, &attestation); err != nil {
			continue // Try next line
		}

		// Check if this is an in-toto statement
		if strings.Contains(attestation.PayloadType, "intoto") ||
			strings.Contains(attestation.PayloadType, "dsse") {

			// Decode and check predicate type
			// For now, just trust that cosign --type slsaprovenance filtered correctly
			foundProvenance = true
			break
		}
	}

	if !foundProvenance {
		return fmt.Errorf("no valid SLSA provenance attestation found in cosign output")
	}

	return nil
}
