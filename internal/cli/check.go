package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/differ"
	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/observability"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	otelobs "github.com/mcptrust/mcptrust/internal/observability/otel"
	"github.com/mcptrust/mcptrust/internal/observability/receipt"
	"github.com/mcptrust/mcptrust/internal/policy"
	"github.com/mcptrust/mcptrust/internal/scanner"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// checkCmd verifies current server state against lockfile
var checkCmd = &cobra.Command{
	Use:   "check --lock <lockfile> [-- <command>]",
	Short: "Check MCP server against lockfile for drift",
	Long: `Scans the MCP server and compares against lockfile to detect capability drift.

Fails if any prompts, templates, or tools have been added, removed, or changed
since the lockfile was created. Optionally applies policy evaluation.

By default, drift enforcement is applied via --fail-on. Policy evaluation is
optional and can be enabled with --policy.

Examples:
  # Check using command from lockfile
  mcptrust check --lock mcp-lock.json -- "npx -y @modelcontextprotocol/server-filesystem /tmp"

  # Check with policy preset
  mcptrust check --lock mcp-lock.json --policy=baseline -- "npx ..."

  # Fail only on critical drift (default)
  mcptrust check --lock mcp-lock.json --fail-on=critical -- "npx ..."

  # Get JSON output for CI
  mcptrust check --lock mcp-lock.json --format=json -- "npx ..."`,
	RunE:         runCheck,
	SilenceUsage: true,
}

var (
	checkLockFlag    string
	checkTimeoutFlag time.Duration
	checkFailOnFlag  string
	checkFormatFlag  string
	checkPolicyFlag  string
)

func init() {
	checkCmd.Flags().StringVar(&checkLockFlag, "lock", defaultLockfilePath, "Path to lockfile")
	checkCmd.Flags().DurationVarP(&checkTimeoutFlag, "timeout", "t", defaultTimeout, "Timeout for MCP operations")
	checkCmd.Flags().StringVar(&checkFailOnFlag, "fail-on", "critical", "Severity threshold for failure: critical, moderate, or info")
	checkCmd.Flags().StringVar(&checkFormatFlag, "format", "text", "Output format: text or json")
	checkCmd.Flags().StringVar(&checkPolicyFlag, "policy", "", "Policy to apply: baseline, strict, or path to YAML file")
}

// GetCheckCmd export
func GetCheckCmd() *cobra.Command {
	return checkCmd
}

func runCheck(cmd *cobra.Command, args []string) (err error) {
	ctx := cmd.Context()
	sess := receipt.Start(ctx, "mcptrust check", os.Args[1:])
	var receiptOpts []receipt.Option

	defer func() {
		receiptOpts = append(receiptOpts, receipt.WithLockfile(checkLockFlag))
		_ = sess.Finish(err, receiptOpts...)
	}()

	log := logging.From(ctx)
	start := time.Now()

	// Start OTel span if enabled
	if h := otelobs.From(ctx); h != nil {
		var span trace.Span
		ctx, span = h.Tracer.Start(ctx, "mcptrust.check",
			trace.WithAttributes(
				attribute.String("mcptrust.op_id", observability.OpID(ctx)),
				attribute.String("mcptrust.command", "check"),
				attribute.String("mcptrust.lockfile", checkLockFlag),
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

	log.Event(ctx, "check.start", nil)

	var resultStatus string
	defer func() {
		log.Event(ctx, "check.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
	}()

	// Parse fail-on level
	failOn, parseErr := ParseFailOnLevel(checkFailOnFlag)
	if parseErr != nil {
		resultStatus = "fail"
		return parseErr
	}

	// Validate format
	if checkFormatFlag != "text" && checkFormatFlag != "json" {
		resultStatus = "fail"
		return fmt.Errorf("invalid format: %s (use text or json)", checkFormatFlag)
	}

	// Load lockfile
	manager := locker.NewManager()
	if !manager.Exists(checkLockFlag) {
		resultStatus = "fail"
		return fmt.Errorf("lockfile not found: %s (run 'mcptrust lock' first)", checkLockFlag)
	}

	// Detect version and load appropriately
	version, err := manager.DetectLockfileVersion(checkLockFlag)
	if err != nil {
		resultStatus = "fail"
		return fmt.Errorf("failed to detect lockfile version: %w", err)
	}

	// Only support v3 for check command
	if !strings.HasPrefix(version, "3.") {
		resultStatus = "fail"
		return fmt.Errorf("check command requires v3 lockfile (found version %s); regenerate with 'mcptrust lock --v3'", version)
	}

	lockfile, loadErr := manager.LoadV3(checkLockFlag)
	if loadErr != nil {
		resultStatus = "fail"
		return fmt.Errorf("failed to load lockfile: %w", loadErr)
	}

	// Get command: from args or need explicit command
	command := extractCommand(args)
	if command == "" {
		// v3 lockfiles don't store serverCommand, so we need explicit command
		resultStatus = "fail"
		return fmt.Errorf("no MCP server command provided. Usage: mcptrust check --lock <lockfile> -- <command>")
	}

	// Timeout context
	ctx, cancel := context.WithTimeout(ctx, checkTimeoutFlag)
	defer cancel()

	// Suppress scanning message for JSON output
	if checkFormatFlag == "text" {
		fmt.Println("Scanning MCP server...")
	}

	report, scanErr := scanner.Scan(ctx, command, checkTimeoutFlag)
	if scanErr != nil {
		resultStatus = "fail"
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	if report.Error != "" {
		resultStatus = "fail"
		return fmt.Errorf("scan error: %s", report.Error)
	}

	// Compare using v3 differ
	driftResult, compareErr := differ.CompareV3(lockfile, report)
	if compareErr != nil {
		resultStatus = "fail"
		return fmt.Errorf("comparison failed: %w", compareErr)
	}

	// Load and evaluate policy if specified
	var policyResults []models.PolicyResult
	var policyPreset string
	if checkPolicyFlag != "" {
		policyConfig, loadPolicyErr := loadPolicyWithPreset(checkPolicyFlag, checkPolicyFlag)
		if loadPolicyErr != nil {
			resultStatus = "fail"
			return fmt.Errorf("failed to load policy: %w", loadPolicyErr)
		}
		policyPreset = checkPolicyFlag

		engine, engErr := policy.NewEngine()
		if engErr != nil {
			resultStatus = "fail"
			return fmt.Errorf("failed to create policy engine: %w", engErr)
		}

		// Build v3 policy input with drift
		policyInput := policy.BuildV3PolicyInput(lockfile, report, driftResult)

		policyResults, err = engine.EvaluateWithV3Input(policyConfig, &policyInput)
		if err != nil {
			resultStatus = "fail"
			return fmt.Errorf("policy evaluation failed: %w", err)
		}
	}

	// Build check result
	checkResult := BuildCheckResult(
		lockfile.LockFileVersion,
		lockfile.Server.Name,
		checkLockFlag,
		driftResult,
		policyResults,
		policyPreset,
		failOn,
	)

	// Output result
	if checkFormatFlag == "json" {
		jsonOutput, jsonErr := FormatJSONOutput(checkResult)
		if jsonErr != nil {
			resultStatus = "fail"
			return fmt.Errorf("failed to format JSON output: %w", jsonErr)
		}
		fmt.Println(string(jsonOutput))
	} else {
		fmt.Print(FormatTextOutput(checkResult))
	}

	// Determine exit code - use os.Exit to avoid Cobra error messages corrupting JSON
	if checkResult.Outcome == "FAIL" {
		resultStatus = "fail"
		// For JSON format, exit without returning error to avoid "Error: ..." corrupting stdout
		if checkFormatFlag == "json" {
			os.Exit(1)
		}
		// For text format, return error for visibility
		if checkResult.Policy != nil && !checkResult.Policy.Passed {
			return fmt.Errorf("policy check failed")
		}
		return fmt.Errorf("drift detected: %d change(s) found", checkResult.Summary.Total)
	}

	resultStatus = "success"
	return nil
}
