package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mcptrust/mcptrust/internal/artifact"
	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/observability"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	otelobs "github.com/mcptrust/mcptrust/internal/observability/otel"
	"github.com/mcptrust/mcptrust/internal/observability/receipt"
	"github.com/mcptrust/mcptrust/internal/scanner"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultLockfilePath = "mcp-lock.json"
)

// colors
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

// lockCmd scans server capabilites
var lockCmd = &cobra.Command{
	Use:   "lock -- <command>",
	Short: "Lock MCP server capabilities",
	Long: `Scans server and creates mcp-lock.json capturing current capabilities.
Facilitates drift detection.

Example:
  mcptrust lock -- "npx -y @modelcontextprotocol/server-filesystem /tmp"`,
	RunE: runLock,
}

var (
	lockTimeoutFlag          time.Duration
	lockOutputFlag           string
	lockForceFlag            bool
	lockPinFlag              bool
	lockVerifyProvenanceFlag bool
	lockExpectedSourceFlag   string
	lockV3Flag               bool
)

func init() {
	lockCmd.Flags().DurationVarP(&lockTimeoutFlag, "timeout", "t", defaultTimeout, "Timeout for MCP operations")
	lockCmd.Flags().StringVarP(&lockOutputFlag, "output", "o", defaultLockfilePath, "Output path for the lockfile")
	lockCmd.Flags().BoolVarP(&lockForceFlag, "force", "f", false, "Overwrite lockfile even if drift is detected")
	lockCmd.Flags().BoolVar(&lockPinFlag, "pin", false, "Resolve and pin artifact (npm/OCI) coordinates for supply chain security")
	lockCmd.Flags().BoolVar(&lockVerifyProvenanceFlag, "verify-provenance", false, "Verify SLSA/Sigstore provenance attestations")
	lockCmd.Flags().StringVar(&lockExpectedSourceFlag, "expected-source", "", "Expected source repository pattern (regex) for provenance verification")
	lockCmd.Flags().BoolVar(&lockV3Flag, "v3", false, "Generate lockfile v3 format with prompts and resource templates")
}

// GetLockCmd export
func GetLockCmd() *cobra.Command {
	return lockCmd
}

func runLock(cmd *cobra.Command, args []string) (err error) {
	// Get context and start receipt session immediately for early-return coverage
	ctx := cmd.Context()
	sess := receipt.Start(ctx, "mcptrust lock", os.Args[1:])
	var receiptOpts []receipt.Option
	var lockfilePath string

	defer func() {
		receiptOpts = append(receiptOpts, receipt.WithLockfile(lockfilePath))
		_ = sess.Finish(err, receiptOpts...)
	}()

	// command after '--'
	command := extractCommand(args)
	if command == "" {
		return fmt.Errorf("no MCP server command provided. Usage: mcptrust lock -- <command>")
	}

	// Get logger
	log := logging.From(ctx)
	start := time.Now()

	// Start OTel span if enabled (before log.Event so trace_id is available)
	if h := otelobs.From(ctx); h != nil {
		var span trace.Span
		ctx, span = h.Tracer.Start(ctx, "mcptrust.lock",
			trace.WithAttributes(
				attribute.String("mcptrust.op_id", observability.OpID(ctx)),
				attribute.String("mcptrust.command", "lock"),
			))
		defer func() {
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed")
			} else {
				span.SetStatus(codes.Ok, "success")
			}
			span.End()
		}()
	}

	// Emit start event (after span so trace_id is in context)
	log.Event(ctx, "lock.start", nil)

	var resultStatus string
	defer func() {
		log.Event(ctx, "lock.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
	}()

	lockfilePath = lockOutputFlag // Set for receipt

	ctx, cancel := context.WithTimeout(ctx, lockTimeoutFlag)
	defer cancel()

	fmt.Println("Scanning MCP server...")
	report, scanErr := scanner.Scan(ctx, command, lockTimeoutFlag)
	if scanErr != nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	if report.Error != "" {
		return fmt.Errorf("scan error: %s", report.Error)
	}

	manager := locker.NewManager()

	// V3 lockfile path
	if lockV3Flag {
		return runLockV3(ctx, cmd, report, manager, command)
	}

	// V2 (legacy) lockfile path
	newLockfile, createErr := manager.CreateLockfile(report)
	if createErr != nil {
		return fmt.Errorf("failed to create lockfile: %w", createErr)
	}

	// Resolve and pin artifact if --pin flag is set
	if lockPinFlag {
		fmt.Println("Resolving artifact coordinates...")
		pin, pinErr := artifact.CreatePin(ctx, command)
		if pinErr != nil {
			return fmt.Errorf("failed to pin artifact: %w", pinErr)
		}
		if pin == nil {
			fmt.Printf("%s⚠ Artifact type 'local' cannot be pinned%s\n", colorRed, colorReset)
		} else {
			newLockfile.Artifact = pin
			fmt.Printf("%s✓ Artifact pinned: %s@%s%s\n", colorGreen, pin.Name, pin.Version, colorReset)
			if pin.Integrity != "" {
				fmt.Printf("  Integrity: %s\n", truncateString(pin.Integrity, 60))
			}

			// Verify provenance if --verify-provenance is set
			if lockVerifyProvenanceFlag {
				fmt.Println("\nVerifying provenance attestations...")
				provenanceInfo, provErr := artifact.VerifyProvenance(ctx, pin, lockExpectedSourceFlag)
				if provErr != nil {
					return fmt.Errorf("provenance verification failed: %w", provErr)
				}

				// Enforce cosign_slsa for --expected-source (fail-closed)
				if lockExpectedSourceFlag != "" && provenanceInfo.Method != models.ProvenanceMethodCosignSLSA {
					return fmt.Errorf("--expected-source requires SLSA provenance (cosign). npm audit signatures do not expose configSource.uri")
				}

				pin.Provenance = provenanceInfo

				// Method-aware output
				switch provenanceInfo.Method {
				case models.ProvenanceMethodCosignSLSA:
					fmt.Printf("%s✓ SLSA provenance verified (cosign)%s\n", colorGreen, colorReset)
					if provenanceInfo.SourceRepo != "" {
						fmt.Printf("  Source: %s\n", provenanceInfo.SourceRepo)
					}
					if provenanceInfo.BuilderID != "" {
						fmt.Printf("  Builder: %s\n", truncateString(provenanceInfo.BuilderID, 60))
					}
				case models.ProvenanceMethodNPMAuditSigs:
					fmt.Printf("%s✓ Package signature verified (npm audit signatures)%s\n", colorGreen, colorReset)
					fmt.Printf("  Note: SLSA metadata unavailable with npm fallback\n")
				default:
					// Unverified - user explicitly requested provenance but verification failed or not available
					fmt.Printf("%sℹ Provenance not verified%s\n", colorYellow, colorReset)
				}

				// Compute tarball SHA256 since we're doing full verification anyway
				if pin.Type == "npm" && pin.TarballURL != "" {
					fmt.Println("\nComputing tarball SHA256...")
					tarballResult, err := artifact.DownloadTarballForVerification(ctx, pin, false)
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s⚠ Warning: could not download tarball for SHA256: %v%s\n", colorRed, err, colorReset)
					} else {
						defer tarballResult.Cleanup()
						sha256Hash, err := computeTarballSHA256(tarballResult.Path)
						if err != nil {
							fmt.Fprintf(os.Stderr, "%s⚠ Warning: could not compute SHA256: %v%s\n", colorRed, err, colorReset)
						} else {
							pin.TarballSHA256 = sha256Hash
							pin.TarballSize = tarballResult.Size
							fmt.Printf("%s✓ SHA256: %s%s\n", colorGreen, truncateString(sha256Hash, 24)+"...", colorReset)
						}
					}
				}
			}
		}
	} else if lockVerifyProvenanceFlag {
		// --verify-provenance without --pin is an error
		return fmt.Errorf("--verify-provenance requires --pin flag (run 'mcptrust lock --pin --verify-provenance')")
	}

	// Add artifact to receipt options if pinned
	if newLockfile.Artifact != nil {
		artSum := receipt.ArtifactSummary{
			Type:          string(newLockfile.Artifact.Type),
			Name:          newLockfile.Artifact.Name,
			Version:       newLockfile.Artifact.Version,
			Registry:      newLockfile.Artifact.Registry,
			Integrity:     newLockfile.Artifact.Integrity,
			TarballSHA256: newLockfile.Artifact.TarballSHA256,
		}
		if newLockfile.Artifact.Provenance != nil {
			artSum.Provenance = &receipt.ProvenanceSummary{
				Method:     string(newLockfile.Artifact.Provenance.Method),
				Verified:   newLockfile.Artifact.Provenance.Verified,
				SourceRepo: newLockfile.Artifact.Provenance.SourceRepo,
				BuilderID:  newLockfile.Artifact.Provenance.BuilderID,
				VerifiedAt: newLockfile.Artifact.Provenance.VerifiedAt,
			}
		}
		receiptOpts = append(receiptOpts, receipt.WithArtifact(artSum))
	}

	// check for drift
	if manager.Exists(lockOutputFlag) {
		existingLockfile, err := manager.Load(lockOutputFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sWarning: Could not load existing lockfile: %v%s\n", colorRed, err, colorReset)
		} else {
			drifts := manager.DetectDrift(existingLockfile, newLockfile)

			// Check if artifact pin has changed
			artifactChanged := false
			if existingLockfile.Artifact == nil && newLockfile.Artifact != nil {
				artifactChanged = true
			} else if existingLockfile.Artifact != nil && newLockfile.Artifact == nil {
				artifactChanged = true
			} else if existingLockfile.Artifact != nil && newLockfile.Artifact != nil {
				// Simple comparison of relevant fields
				if existingLockfile.Artifact.Name != newLockfile.Artifact.Name ||
					existingLockfile.Artifact.Version != newLockfile.Artifact.Version ||
					existingLockfile.Artifact.Integrity != newLockfile.Artifact.Integrity {
					artifactChanged = true
				}
				// Also check provenance
				if existingLockfile.Artifact.Provenance == nil && newLockfile.Artifact.Provenance != nil {
					artifactChanged = true
				} else if existingLockfile.Artifact.Provenance != nil && newLockfile.Artifact.Provenance == nil {
					artifactChanged = true
				}
			}

			if len(drifts) > 0 {
				fmt.Fprintf(os.Stderr, "\n%s╔══════════════════════════════════════╗%s\n", colorRed, colorReset)
				fmt.Fprintf(os.Stderr, "%s║         DRIFT DETECTED!              ║%s\n", colorRed, colorReset)
				fmt.Fprintf(os.Stderr, "%s╚══════════════════════════════════════╝%s\n\n", colorRed, colorReset)

				for _, drift := range drifts {
					fmt.Fprintf(os.Stderr, "%s  ✗ %s%s\n", colorRed, locker.FormatDriftError(drift), colorReset)
				}
				fmt.Fprintln(os.Stderr)

				if !lockForceFlag {
					fmt.Fprintf(os.Stderr, "Use --force to overwrite the lockfile anyway.\n")
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "%sForce flag set, overwriting lockfile...%s\n", colorRed, colorReset)
			} else if !artifactChanged {
				fmt.Printf("%s✓ No drift detected - lockfile is up to date%s\n", colorGreen, colorReset)
				return nil
			} else {
				// Artifact changed but no tool drift -> proceed to save
				fmt.Printf("%s✓ Updating lockfile with new artifact information%s\n", colorGreen, colorReset)
			}
		}
	}

	if saveErr := manager.Save(newLockfile, lockOutputFlag); saveErr != nil {
		return fmt.Errorf("failed to save lockfile: %w", saveErr)
	}

	fmt.Printf("%s✓ Lockfile created: %s%s\n", colorGreen, lockOutputFlag, colorReset)
	fmt.Printf("  Locked %d tool(s)\n", len(newLockfile.Tools))

	resultStatus = "success"
	return nil
}

// truncateString shortens to maxLen + ...
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// computeTarballSHA256 hashes a file
func computeTarballSHA256(path string) (string, error) {
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

// runLockV3 generates a v3 lockfile with prompts and resource templates
func runLockV3(ctx context.Context, _ *cobra.Command, report *models.ScanReport, manager *locker.Manager, command string) error {
	builder := locker.NewBuilderV3()
	lockfile, err := builder.Build(report)
	if err != nil {
		return fmt.Errorf("failed to build v3 lockfile: %w", err)
	}

	// Resolve and pin artifact if --pin flag is set
	if lockPinFlag {
		fmt.Println("Resolving artifact coordinates...")
		pin, pinErr := artifact.CreatePin(ctx, command)
		if pinErr != nil {
			return fmt.Errorf("failed to pin artifact: %w", pinErr)
		}
		if pin == nil {
			fmt.Printf("%s⚠ Artifact type 'local' cannot be pinned%s\n", colorRed, colorReset)
		} else {
			builder.SetArtifact(lockfile, pin)
			fmt.Printf("%s✓ Artifact pinned: %s@%s%s\n", colorGreen, pin.Name, pin.Version, colorReset)
			if pin.Integrity != "" {
				fmt.Printf("  Integrity: %s\n", truncateString(pin.Integrity, 60))
			}

			// Verify provenance if --verify-provenance is set
			if lockVerifyProvenanceFlag {
				fmt.Println("\nVerifying provenance attestations...")
				provenanceInfo, provErr := artifact.VerifyProvenance(ctx, pin, lockExpectedSourceFlag)
				if provErr != nil {
					return fmt.Errorf("provenance verification failed: %w", provErr)
				}

				// Enforce cosign_slsa for --expected-source
				if lockExpectedSourceFlag != "" && provenanceInfo.Method != models.ProvenanceMethodCosignSLSA {
					return fmt.Errorf("--expected-source requires SLSA provenance (cosign). npm audit signatures do not expose configSource.uri")
				}

				pin.Provenance = provenanceInfo

				switch provenanceInfo.Method {
				case models.ProvenanceMethodCosignSLSA:
					fmt.Printf("%s✓ SLSA provenance verified (cosign)%s\n", colorGreen, colorReset)
					if provenanceInfo.SourceRepo != "" {
						fmt.Printf("  Source: %s\n", provenanceInfo.SourceRepo)
					}
					if provenanceInfo.BuilderID != "" {
						fmt.Printf("  Builder: %s\n", truncateString(provenanceInfo.BuilderID, 60))
					}
				case models.ProvenanceMethodNPMAuditSigs:
					fmt.Printf("%s✓ Package signature verified (npm audit signatures)%s\n", colorGreen, colorReset)
					fmt.Printf("  Note: SLSA metadata unavailable with npm fallback\n")
				default:
					fmt.Printf("%sℹ Provenance not verified%s\n", colorYellow, colorReset)
				}

				// Compute tarball SHA256
				if pin.Type == "npm" && pin.TarballURL != "" {
					fmt.Println("\nComputing tarball SHA256...")
					tarballResult, err := artifact.DownloadTarballForVerification(ctx, pin, false)
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s⚠ Warning: could not download tarball for SHA256: %v%s\n", colorRed, err, colorReset)
					} else {
						defer tarballResult.Cleanup()
						sha256Hash, err := computeTarballSHA256(tarballResult.Path)
						if err != nil {
							fmt.Fprintf(os.Stderr, "%s⚠ Warning: could not compute SHA256: %v%s\n", colorRed, err, colorReset)
						} else {
							pin.TarballSHA256 = sha256Hash
							pin.TarballSize = tarballResult.Size
							fmt.Printf("%s✓ SHA256: %s%s\n", colorGreen, truncateString(sha256Hash, 24)+"...", colorReset)
						}
					}
				}
			}
		}
	} else if lockVerifyProvenanceFlag {
		return fmt.Errorf("--verify-provenance requires --pin flag")
	}

	if err := manager.SaveV3(lockfile, lockOutputFlag); err != nil {
		return fmt.Errorf("failed to save lockfile: %w", err)
	}

	fmt.Printf("\n%s✓ Lockfile v3 created: %s%s\n", colorGreen, lockOutputFlag, colorReset)
	fmt.Printf("  Prompts: %d\n", len(lockfile.Prompts.Definitions))
	fmt.Printf("  Templates: %d\n", len(lockfile.Resources.Templates))
	fmt.Printf("  Tools: %d\n", len(lockfile.Tools))

	return nil
}
