package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/observability"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	otelobs "github.com/mcptrust/mcptrust/internal/observability/otel"
	"github.com/mcptrust/mcptrust/internal/observability/receipt"
	"github.com/mcptrust/mcptrust/internal/runner"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// runCmd is the command for enforced execution
var runCmd = &cobra.Command{
	Use:   "run --lock <lockfile> [-- <command>]",
	Short: "Execute MCP server from verified artifact",
	Long: `Enforced execution of an MCP server from a verified local artifact.

This command ensures the executed artifact matches the pinned artifact,
preventing the registry from serving unverified code.

1. Download artifact
2. Verify integrity
3. Verify provenance (unless disabled)
4. Install from verified local tarball
5. Execute binary directly

Examples:
  # Use command from lockfile
  mcptrust run --lock mcp-lock.json

  # Override command (must match pinned artifact)
  mcptrust run --lock mcp-lock.json -- "npx -y @scope/pkg /custom/path"

  # Dry run - verify everything but don't execute
  mcptrust run --dry-run --lock mcp-lock.json

  # Bypass provenance check (NOT recommended)
  mcptrust run --require-provenance=false --lock mcp-lock.json`,
	RunE: runRun,
}

var (
	runLockFlag                    string
	runTimeoutFlag                 time.Duration
	runDryRunFlag                  bool
	runKeepTempFlag                bool
	runRequireProvenanceFlag       bool
	runExpectedSourceFlag          string
	runBinFlag                     string
	runAllowMissingIntegrityFlag   bool
	runUnsafeAllowPrivateHostsFlag bool
)

func init() {
	runCmd.Flags().StringVar(&runLockFlag, "lock", "", "Path to lockfile (required)")
	runCmd.Flags().DurationVar(&runTimeoutFlag, "timeout", 0, "Execution timeout (0 = no timeout, default for long-lived MCP servers)")
	runCmd.Flags().BoolVar(&runDryRunFlag, "dry-run", false, "Verify everything but don't execute")
	runCmd.Flags().BoolVar(&runKeepTempFlag, "keep-temp", false, "Don't delete temp directory (debug)")
	runCmd.Flags().BoolVar(&runRequireProvenanceFlag, "require-provenance", true, "Require provenance verification")
	runCmd.Flags().StringVar(&runExpectedSourceFlag, "expected-source", "", "Expected source repository pattern (regex)")
	runCmd.Flags().StringVar(&runBinFlag, "bin", "", "Binary name for packages with multiple exports")
	runCmd.Flags().BoolVar(&runAllowMissingIntegrityFlag, "allow-missing-installed-integrity", false,
		"Proceed with warning if installed integrity cannot be verified (NOT recommended)")

	if err := runCmd.MarkFlagRequired("lock"); err != nil {
		// Flag marking is best-effort
		_ = err
	}

	// Hidden flag for enterprise use - requires deliberate action
	runCmd.Flags().BoolVar(&runUnsafeAllowPrivateHostsFlag, "unsafe-allow-private-tarball-hosts", false,
		"SECURITY WEAKENING: Allow tarball downloads from private/internal networks (RFC1918). "+
			"Only use if your npm registry is on a private network.")
}

// GetRunCmd - obvious
func GetRunCmd() *cobra.Command {
	return runCmd
}

func runRun(cmd *cobra.Command, args []string) (err error) {
	// Get context and start receipt session immediately for early-return coverage
	ctx := cmd.Context()
	sess := receipt.Start(ctx, "mcptrust run", os.Args[1:])
	var receiptOpts []receipt.Option

	defer func() {
		_ = sess.Finish(err, receiptOpts...)
	}()

	// Get logger
	log := logging.From(ctx)
	start := time.Now()

	// Start OTel span if enabled (before log.Event so trace_id is available)
	if h := otelobs.From(ctx); h != nil {
		var span trace.Span
		ctx, span = h.Tracer.Start(ctx, "mcptrust.run",
			trace.WithAttributes(
				attribute.String("mcptrust.op_id", observability.OpID(ctx)),
				attribute.String("mcptrust.command", "run"),
				attribute.String("mcptrust.lockfile", runLockFlag),
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
	log.Event(ctx, "run.start", nil)

	var resultStatus string
	defer func() {
		log.Event(ctx, "run.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
	}()

	// Load lockfile
	if runLockFlag == "" {
		resultStatus = "fail"
		return fmt.Errorf("--lock flag is required")
	}

	manager := locker.NewManager()
	lockfile, loadErr := manager.Load(runLockFlag)
	if loadErr != nil {
		resultStatus = "fail"
		return fmt.Errorf("failed to load lockfile: %w", loadErr)
	}

	// Add lockfile to receipt
	receiptOpts = append(receiptOpts, receipt.WithLockfile(runLockFlag))

	// Check for artifact pin
	if lockfile.Artifact == nil {
		resultStatus = "fail"
		return fmt.Errorf("lockfile has no artifact pin; run 'mcptrust lock --pin' first")
	}

	// Add artifact to receipt
	artSum := receipt.ArtifactSummary{
		Type:          string(lockfile.Artifact.Type),
		Name:          lockfile.Artifact.Name,
		Version:       lockfile.Artifact.Version,
		Registry:      lockfile.Artifact.Registry,
		Integrity:     lockfile.Artifact.Integrity,
		TarballSHA256: lockfile.Artifact.TarballSHA256,
	}
	if lockfile.Artifact.Provenance != nil {
		artSum.Provenance = &receipt.ProvenanceSummary{
			Method:     string(lockfile.Artifact.Provenance.Method),
			Verified:   lockfile.Artifact.Provenance.Verified,
			SourceRepo: lockfile.Artifact.Provenance.SourceRepo,
			BuilderID:  lockfile.Artifact.Provenance.BuilderID,
			VerifiedAt: lockfile.Artifact.Provenance.VerifiedAt,
		}
	}
	receiptOpts = append(receiptOpts, receipt.WithArtifact(artSum))

	// Get command override if provided after --
	var commandOverride string
	if len(args) > 0 {
		// The command comes from args after --
		// Cobra passes these as separate args, join them back
		for _, arg := range args {
			if commandOverride != "" {
				commandOverride += " "
			}
			commandOverride += arg
		}
	}

	// If no override and no server command in lockfile, error
	if commandOverride == "" && lockfile.ServerCommand == "" {
		return fmt.Errorf("no server command in lockfile and no command override provided")
	}

	// Get the appropriate runner for the artifact type
	r, err := runner.GetRunner(lockfile.Artifact.Type)
	if err != nil {
		return err
	}

	// Build context with timeout (use ctx from cmd.Context for logging)
	if runTimeoutFlag > 0 && !runDryRunFlag {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, runTimeoutFlag)
		defer cancel()
	}

	// Build run config
	config := &runner.RunConfig{
		Lockfile:                       lockfile,
		LockfilePath:                   runLockFlag,
		DryRun:                         runDryRunFlag,
		KeepTemp:                       runKeepTempFlag,
		RequireProvenance:              runRequireProvenanceFlag,
		ExpectedSource:                 runExpectedSourceFlag,
		Timeout:                        runTimeoutFlag,
		CommandOverride:                commandOverride,
		BinName:                        runBinFlag,
		AllowMissingInstalledIntegrity: runAllowMissingIntegrityFlag,
		AllowPrivateTarballHosts:       runUnsafeAllowPrivateHostsFlag,
	}

	// LOUD WARNING if security is being weakened
	if runUnsafeAllowPrivateHostsFlag {
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

	// Run
	result, runErr := r.Run(ctx, config)
	if runErr != nil {
		resultStatus = "fail"
		return runErr
	}

	// Exit with the same code as the executed command
	if result.ExitCode != 0 {
		resultStatus = "fail"
		err = fmt.Errorf("exit code %d", result.ExitCode)
		os.Exit(result.ExitCode)
	}

	resultStatus = "success"
	return nil
}
