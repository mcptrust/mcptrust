package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/artifact"
	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	"github.com/mcptrust/mcptrust/internal/observability/receipt"
	"github.com/mcptrust/mcptrust/internal/runner"
	"github.com/spf13/cobra"
)

// artifactCmd is the parent command for artifact operations
var artifactCmd = &cobra.Command{
	Use:   "artifact",
	Short: "Artifact verification commands",
	Long:  `Verify artifact integrity and provenance attestations.`,
}

// artifactVerifyCmd
var artifactVerifyCmd = &cobra.Command{
	Use:   "verify [lockfile]",
	Short: "Verify artifact integrity",
	Long: `Fetches current registry metadata and compares against lockfile pin.
npm: integrity hash. OCI: digest.`,
	SilenceUsage: true,
	RunE:         runArtifactVerify,
}

// artifactProvenanceCmd
var artifactProvenanceCmd = &cobra.Command{
	Use:   "provenance [lockfile]",
	Short: "Verify provenance attestations",
	Long: `Verifies SLSA/Sigstore attestations.
npm: cosign verify-blob-attestation (or audit sigs fallback).
OCI: cosign verify-attestation.`,
	SilenceUsage: true,
	RunE:         runArtifactProvenance,
}

var (
	artifactLockfile                    string
	artifactExpectedSource              string
	artifactJSONOutput                  bool
	artifactTimeout                     time.Duration
	artifactDeepVerify                  bool
	artifactUnsafeAllowPrivateHostsFlag bool
)

func init() {
	// Verify command
	artifactVerifyCmd.Flags().StringVarP(&artifactLockfile, "lockfile", "l", "mcp-lock.json", "Path to lockfile")
	artifactVerifyCmd.Flags().DurationVarP(&artifactTimeout, "timeout", "t", 30*time.Second, "Timeout for registry operations")
	artifactVerifyCmd.Flags().BoolVar(&artifactDeepVerify, "deep", false, "Download tarball and verify SHA256/SRI")
	artifactVerifyCmd.Flags().BoolVar(&artifactUnsafeAllowPrivateHostsFlag, "unsafe-allow-private-tarball-hosts", false,
		"SECURITY WEAKENING: Allow tarball downloads from private networks (requires --deep)")

	// Provenance command
	artifactProvenanceCmd.Flags().StringVarP(&artifactLockfile, "lockfile", "l", "mcp-lock.json", "Path to lockfile")
	artifactProvenanceCmd.Flags().StringVar(&artifactExpectedSource, "expected-source", "", "Expected source repository pattern (regex)")
	artifactProvenanceCmd.Flags().BoolVar(&artifactJSONOutput, "json", false, "Output as JSON")
	artifactProvenanceCmd.Flags().DurationVarP(&artifactTimeout, "timeout", "t", 60*time.Second, "Timeout for verification operations")

	artifactCmd.AddCommand(artifactVerifyCmd)
	artifactCmd.AddCommand(artifactProvenanceCmd)
}

// GetArtifactCmd returns the artifact command
func GetArtifactCmd() *cobra.Command {
	return artifactCmd
}

func runArtifactVerify(cmd *cobra.Command, args []string) error {
	// Get logger and emit start event
	ctx := cmd.Context()
	log := logging.From(ctx)
	start := time.Now()
	log.Event(ctx, "artifact_verify.start", nil)

	var resultStatus string

	// Receipt session
	sess := receipt.Start(ctx, "mcptrust artifact verify", os.Args[1:])
	var receiptOpts []receipt.Option
	var resultErr error

	defer func() {
		log.Event(ctx, "artifact_verify.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
		// Write receipt
		_ = sess.Finish(resultErr, receiptOpts...)
	}()

	// Handle positional lockfile argument
	lockfilePath := artifactLockfile
	if len(args) > 0 {
		lockfilePath = args[0]
	}

	// Load lockfile
	manager := locker.NewManager()
	if !manager.Exists(lockfilePath) {
		resultStatus = "fail"
		return fmt.Errorf("lockfile not found: %s", lockfilePath)
	}

	lockfile, err := manager.Load(lockfilePath)
	if err != nil {
		resultStatus = "fail"
		return fmt.Errorf("failed to load lockfile: %w", err)
	}

	// Check if artifact is pinned
	if lockfile.Artifact == nil {
		resultStatus = "fail"
		resultErr = fmt.Errorf("no artifact pin found in lockfile. Run 'mcptrust lock --pin' first")
		return resultErr
	}

	// Validate flag combinations
	if artifactUnsafeAllowPrivateHostsFlag && !artifactDeepVerify {
		resultStatus = "fail"
		resultErr = fmt.Errorf("--unsafe-allow-private-tarball-hosts requires --deep flag")
		return resultErr
	}

	pin := lockfile.Artifact

	// Add artifact to receipt
	artSum := receipt.ArtifactSummary{
		Type:          string(pin.Type),
		Name:          pin.Name,
		Version:       pin.Version,
		Registry:      pin.Registry,
		Integrity:     pin.Integrity,
		TarballSHA256: pin.TarballSHA256,
	}
	receiptOpts = append(receiptOpts, receipt.WithArtifact(artSum))

	fmt.Printf("%s%sArtifact Verification%s\n", colorBold, colorYellow, colorReset)
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("Type:      %s\n", pin.Type)

	switch pin.Type {
	case "npm":
		fmt.Printf("Package:   %s@%s\n", pin.Name, pin.Version)
		fmt.Printf("Registry:  %s\n", pin.Registry)
		if pin.Integrity != "" {
			fmt.Printf("Integrity: %s\n", truncateString(pin.Integrity, 60))
		}
	case "oci":
		fmt.Printf("Image:     %s\n", pin.Image)
		if pin.Digest != "" {
			fmt.Printf("Digest:    %s\n", pin.Digest)
		}
	}

	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("\nVerifying against registry...\n\n")

	// Verify
	ctx, cancel := context.WithTimeout(ctx, artifactTimeout)
	defer cancel()

	err = artifact.VerifyPin(ctx, pin)
	if err != nil {
		fmt.Printf("%s✗ Verification FAILED%s\n", colorRed, colorReset)
		fmt.Printf("  %s→ %s%s\n", colorRed, err.Error(), colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s✓ Integrity verified%s\n", colorGreen, colorReset)
	fmt.Printf("  Artifact matches lockfile pin\n")

	// Deep verification: download tarball and verify hashes
	if artifactDeepVerify && pin.Type == "npm" {
		// LOUD WARNING if security is being weakened
		if artifactUnsafeAllowPrivateHostsFlag {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "╔══════════════════════════════════════════════════════════════════╗\n")
			fmt.Fprintf(os.Stderr, "║  ⚠️  SECURITY GUARANTEE WEAKENED                                  ║\n")
			fmt.Fprintf(os.Stderr, "╠══════════════════════════════════════════════════════════════════╣\n")
			fmt.Fprintf(os.Stderr, "║  --unsafe-allow-private-tarball-hosts is enabled.               ║\n")
			fmt.Fprintf(os.Stderr, "║  Tarball downloads from private/internal networks are allowed.  ║\n")
			fmt.Fprintf(os.Stderr, "║  This disables SSRF protection against RFC1918 addresses.       ║\n")
			fmt.Fprintf(os.Stderr, "╚══════════════════════════════════════════════════════════════════╝\n")
			fmt.Fprintf(os.Stderr, "\n")
		}

		fmt.Printf("\nPerforming deep verification...\n")

		tarballResult, err := artifact.DownloadTarballForVerification(ctx, pin, artifactUnsafeAllowPrivateHostsFlag)
		if err != nil {
			fmt.Printf("%s✗ Deep verification FAILED: could not download tarball%s\n", colorRed, colorReset)
			fmt.Printf("  %s→ %s%s\n", colorRed, err.Error(), colorReset)
			os.Exit(1)
		}
		defer tarballResult.Cleanup()

		// Compute and verify SRI
		computedSRI, err := runner.ComputeTarballSRI(tarballResult.Path)
		if err != nil {
			fmt.Printf("%s✗ Deep verification FAILED: could not compute SRI%s\n", colorRed, colorReset)
			fmt.Printf("  %s→ %s%s\n", colorRed, err.Error(), colorReset)
			os.Exit(1)
		}

		if err := runner.VerifyIntegrityMatch(pin.Integrity, computedSRI, "pinned vs downloaded"); err != nil {
			fmt.Printf("%s✗ SRI mismatch%s\n", colorRed, colorReset)
			fmt.Printf("  %s→ %s%s\n", colorRed, err.Error(), colorReset)
			os.Exit(1)
		}
		fmt.Printf("%s✓ SRI verified (downloaded tarball matches pinned)%s\n", colorGreen, colorReset)

		// Verify SHA256 if present
		if pin.TarballSHA256 != "" {
			computedSHA256, err := computeFileSHA256(tarballResult.Path)
			if err != nil {
				fmt.Printf("%s✗ Deep verification FAILED: could not compute SHA256%s\n", colorRed, colorReset)
				fmt.Printf("  %s→ %s%s\n", colorRed, err.Error(), colorReset)
				os.Exit(1)
			}

			if err := runner.VerifySHA256Match(pin.TarballSHA256, computedSHA256, "pinned vs downloaded"); err != nil {
				fmt.Printf("%s✗ SHA256 mismatch%s\n", colorRed, colorReset)
				fmt.Printf("  %s→ %s%s\n", colorRed, err.Error(), colorReset)
				os.Exit(1)
			}
			fmt.Printf("%s✓ SHA256 verified%s\n", colorGreen, colorReset)
		} else {
			fmt.Printf("  (no tarball_sha256 in lockfile, skipping SHA256 verification)\n")
		}
	}

	resultStatus = "success"
	return nil
}

func runArtifactProvenance(cmd *cobra.Command, args []string) error {
	// Get logger and emit start event
	ctx := cmd.Context()
	log := logging.From(ctx)
	start := time.Now()
	log.Event(ctx, "artifact_provenance.start", nil)

	var resultStatus string

	// Receipt session
	sess := receipt.Start(ctx, "mcptrust artifact provenance", os.Args[1:])
	var receiptOpts []receipt.Option
	var resultErr error

	defer func() {
		log.Event(ctx, "artifact_provenance.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
		// Write receipt
		_ = sess.Finish(resultErr, receiptOpts...)
	}()

	// Handle positional lockfile argument
	lockfilePath := artifactLockfile
	if len(args) > 0 {
		lockfilePath = args[0]
	}

	// Load lockfile
	manager := locker.NewManager()
	if !manager.Exists(lockfilePath) {
		resultStatus = "fail"
		return fmt.Errorf("lockfile not found: %s", lockfilePath)
	}

	lockfile, err := manager.Load(lockfilePath)
	if err != nil {
		resultStatus = "fail"
		return fmt.Errorf("failed to load lockfile: %w", err)
	}

	// Check if artifact is pinned
	if lockfile.Artifact == nil {
		resultStatus = "fail"
		resultErr = fmt.Errorf("no artifact pin found in lockfile. Run 'mcptrust lock --pin' first")
		return resultErr
	}

	pin := lockfile.Artifact

	// Add artifact to receipt
	artSum := receipt.ArtifactSummary{
		Type:          string(pin.Type),
		Name:          pin.Name,
		Version:       pin.Version,
		Registry:      pin.Registry,
		Integrity:     pin.Integrity,
		TarballSHA256: pin.TarballSHA256,
	}
	receiptOpts = append(receiptOpts, receipt.WithArtifact(artSum))

	if !artifactJSONOutput {
		fmt.Printf("%s%sProvenance Verification%s\n", colorBold, colorYellow, colorReset)
		fmt.Println(strings.Repeat("-", 50))
		fmt.Printf("Type:      %s\n", pin.Type)

		switch pin.Type {
		case "npm":
			fmt.Printf("Package:   %s@%s\n", pin.Name, pin.Version)
		case "oci":
			fmt.Printf("Image:     %s\n", artifact.GetCanonicalOCIReference(pin))
		}

		if artifactExpectedSource != "" {
			fmt.Printf("Expected:  %s\n", artifactExpectedSource)
		}

		fmt.Println(strings.Repeat("-", 50))
		fmt.Printf("\nVerifying provenance attestations...\n\n")
	}

	// Verify provenance
	ctx, cancel := context.WithTimeout(ctx, artifactTimeout)
	defer cancel()

	provenanceInfo, err := artifact.VerifyProvenance(ctx, pin, artifactExpectedSource)
	if err != nil {
		if !artifactJSONOutput {
			fmt.Printf("%s✗ Provenance verification FAILED%s\n", colorRed, colorReset)
			fmt.Printf("  %s→ %s%s\n", colorRed, err.Error(), colorReset)
		} else {
			result := map[string]interface{}{
				"verified": false,
				"error":    err.Error(),
			}
			_ = json.NewEncoder(os.Stdout).Encode(result)
		}
		os.Exit(1)
	}

	// Enforce cosign_slsa for --expected-source (fail-closed)
	if artifactExpectedSource != "" && provenanceInfo.Method != models.ProvenanceMethodCosignSLSA {
		errMsg := "--expected-source requires SLSA provenance (cosign). npm audit signatures do not expose configSource.uri"
		if !artifactJSONOutput {
			fmt.Printf("%s✗ Expected source verification FAILED%s\n", colorRed, colorReset)
			fmt.Printf("  %s→ %s%s\n", colorRed, errMsg, colorReset)
		} else {
			result := map[string]interface{}{
				"verified": false,
				"error":    errMsg,
			}
			_ = json.NewEncoder(os.Stdout).Encode(result)
		}
		os.Exit(1)
	}

	if artifactJSONOutput {
		// Always include base fields; only include SLSA metadata for cosign_slsa
		provOutput := map[string]interface{}{
			"verified":    provenanceInfo.Verified,
			"method":      string(provenanceInfo.Method),
			"verified_at": provenanceInfo.VerifiedAt,
		}
		// Only include SLSA metadata fields when method is cosign_slsa
		if provenanceInfo.Method == models.ProvenanceMethodCosignSLSA {
			provOutput["predicate_type"] = provenanceInfo.PredicateType
			provOutput["builder_id"] = provenanceInfo.BuilderID
			provOutput["source_repo"] = provenanceInfo.SourceRepo
			provOutput["source_ref"] = provenanceInfo.SourceRef
			provOutput["workflow_uri"] = provenanceInfo.WorkflowURI
		}
		result := map[string]interface{}{
			"verified":   true,
			"provenance": provOutput,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		resultStatus = "success"
		return nil
	}

	// Pretty print provenance info (method-aware)
	switch provenanceInfo.Method {
	case models.ProvenanceMethodCosignSLSA:
		fmt.Printf("%s✓ SLSA provenance verified (cosign)%s\n\n", colorGreen, colorReset)

		if provenanceInfo.BuilderID != "" {
			fmt.Printf("Builder:      %s\n", provenanceInfo.BuilderID)
		}
		if provenanceInfo.SourceRepo != "" {
			fmt.Printf("Source Repo:  %s\n", provenanceInfo.SourceRepo)
		}
		if provenanceInfo.SourceRef != "" {
			fmt.Printf("Source Ref:   %s\n", truncateString(provenanceInfo.SourceRef, 50))
		}
		if provenanceInfo.WorkflowURI != "" {
			fmt.Printf("Workflow:     %s\n", provenanceInfo.WorkflowURI)
		}
		if provenanceInfo.VerifiedAt != "" {
			fmt.Printf("Verified At:  %s\n", provenanceInfo.VerifiedAt)
		}
	case models.ProvenanceMethodNPMAuditSigs:
		fmt.Printf("%s✓ Package signature verified (npm audit signatures)%s\n\n", colorGreen, colorReset)
		fmt.Printf("  Note: npm audit signatures do not expose SLSA provenance metadata\n")
		fmt.Printf("        (source_repo, workflow_uri, builder_id are unavailable)\n")
		if provenanceInfo.VerifiedAt != "" {
			fmt.Printf("\nVerified At:  %s\n", provenanceInfo.VerifiedAt)
		}
	default:
		// Unverified or unknown method - user explicitly requested provenance
		fmt.Printf("%sℹ Provenance not verified%s\n", colorYellow, colorReset)
	}

	resultStatus = "success"
	return nil
}

// computeFileSHA256 computes the SHA256 hash of a file
func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
