package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

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
	"gopkg.in/yaml.v3"
)

// colorBold is an ANSI bold modifier
const colorBold = "\033[1m"

// Default policy when no file is provided
var defaultPolicy = models.PolicyConfig{
	Name: "Default Security Policy",
	Rules: []models.PolicyRule{
		{
			Name:       "No High Risk Tools",
			Expr:       `!input.tools.exists(t, t.risk_level == "HIGH")`,
			FailureMsg: "High risk tool detected!",
		},
	},
}

// policyCmd group
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy management commands",
	Long:  `Manage and enforce security policies.`,
}

// policyCheckCmd
var policyCheckCmd = &cobra.Command{
	Use:   "check -- <command>",
	Short: "Check server against policies",
	Long: `Evaluate server capabilities against YAML policies (CEL rules).

Example:
  mcptrust policy check --policy ./policy.yaml -- "npx -y .../server-fs /tmp"`,
	SilenceUsage: true,
	RunE:         runPolicyCheck,
}

var (
	policyFile     string
	policyPreset   string
	policyTimeout  time.Duration
	policyLockfile string
)

func init() {
	policyCheckCmd.Flags().StringVarP(&policyFile, "policy", "P", "", "Path to policy YAML file (uses default policy if not provided)")
	policyCheckCmd.Flags().StringVar(&policyPreset, "preset", "", "Use built-in policy preset: baseline (warn-only) or strict (fail-closed)")
	policyCheckCmd.Flags().DurationVarP(&policyTimeout, "timeout", "t", 10*time.Second, "Timeout for MCP operations")
	policyCheckCmd.Flags().StringVarP(&policyLockfile, "lockfile", "l", "", "Path to lockfile for artifact-based policies (enables input.artifact and input.provenance)")
	policyCmd.AddCommand(policyCheckCmd)
}

// GetPolicyCmd export
func GetPolicyCmd() *cobra.Command {
	return policyCmd
}

func runPolicyCheck(cmd *cobra.Command, args []string) (err error) {
	// Get context and start receipt session immediately for early-return coverage
	ctx := cmd.Context()
	sess := receipt.Start(ctx, "mcptrust policy check", os.Args[1:])
	var receiptHits []receipt.RuleHit
	var policyStatus string
	var presetName string

	defer func() {
		_ = sess.Finish(err, receipt.WithPolicy(presetName, policyStatus, receiptHits))
	}()

	// command after '--'
	command := extractPolicyCommand(args)
	if command == "" {
		return fmt.Errorf("no MCP server command provided. Usage: mcptrust policy check -- <command>")
	}

	// Get logger
	log := logging.From(ctx)
	start := time.Now()

	// Start OTel span if enabled (before log.Event so trace_id is available)
	if h := otelobs.From(ctx); h != nil {
		var span trace.Span
		ctx, span = h.Tracer.Start(ctx, "mcptrust.policy.check",
			trace.WithAttributes(
				attribute.String("mcptrust.op_id", observability.OpID(ctx)),
				attribute.String("mcptrust.command", "policy check"),
				attribute.String("mcptrust.preset", policyPreset),
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
	log.Event(ctx, "policy_check.start", nil)

	var resultStatus string
	defer func() {
		log.Event(ctx, "policy_check.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
	}()

	policyConfig, loadErr := loadPolicyWithPreset(policyFile, policyPreset)
	if loadErr != nil {
		resultStatus = "fail"
		policyStatus = "fail"
		return fmt.Errorf("failed to load policy: %w", loadErr)
	}
	presetName = policyPreset
	if presetName == "" {
		presetName = "custom"
	}

	fmt.Printf("%s%sPolicy:%s %s\n\n", colorBold, colorYellow, colorReset, policyConfig.Name)

	engine, engErr := policy.NewEngine()
	if engErr != nil {
		resultStatus = "fail"
		return fmt.Errorf("failed to create policy engine: %w", engErr)
	}

	if compErr := engine.CompileAndValidate(policyConfig); compErr != nil {
		resultStatus = "fail"
		return compErr
	}

	fmt.Printf("Scanning MCP server...\n\n")
	ctx, cancel := context.WithTimeout(ctx, policyTimeout)
	defer cancel()

	report, scanErr := scanner.Scan(ctx, command, policyTimeout)
	if scanErr != nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	if report.Error != "" {
		fmt.Printf("%s⚠ Warning:%s Scan completed with errors: %s\n\n", colorYellow, colorReset, report.Error)
	}

	// Load lockfile if specified for artifact-based policies
	var lockfileData *models.Lockfile
	if policyLockfile != "" {
		lockerMgr := locker.NewManager()
		var lockErr error
		lockfileData, lockErr = lockerMgr.Load(policyLockfile)
		if lockErr != nil {
			return fmt.Errorf("failed to load lockfile: %w", lockErr)
		}
		fmt.Printf("Loaded lockfile: %s\n", policyLockfile)
		if lockfileData.Artifact != nil {
			fmt.Printf("  Artifact: %s@%s\n", lockfileData.Artifact.Name, lockfileData.Artifact.Version)
		}
	}

	results, evalErr := engine.EvaluateWithLockfile(policyConfig, report, lockfileData)
	if evalErr != nil {
		return fmt.Errorf("policy evaluation failed: %w", evalErr)
	}

	fmt.Printf("%s%sResults:%s\n", colorBold, colorYellow, colorReset)
	fmt.Println(strings.Repeat("-", 50))

	hasErrors := false
	hasWarnings := false
	for _, result := range results {
		if result.Passed {
			fmt.Printf("%s✓%s %s\n", colorGreen, colorReset, result.RuleName)
		} else {
			// Determine color based on severity
			if result.Severity == models.PolicySeverityWarn {
				hasWarnings = true
				fmt.Printf("%s⚠%s %s\n", colorYellow, colorReset, result.RuleName)
				fmt.Printf("  %s→ %s%s\n", colorYellow, result.FailureMsg, colorReset)
				receiptHits = append(receiptHits, receipt.RuleHit{Name: result.RuleName, Severity: "warn"})
			} else {
				hasErrors = true
				fmt.Printf("%s✗%s %s\n", colorRed, colorReset, result.RuleName)
				fmt.Printf("  %s→ %s%s\n", colorRed, result.FailureMsg, colorReset)
				receiptHits = append(receiptHits, receipt.RuleHit{Name: result.RuleName, Severity: "error"})
			}
		}
	}

	fmt.Println(strings.Repeat("-", 50))

	// Determine exit behavior based on policy mode
	if !hasErrors && !hasWarnings {
		fmt.Printf("\n%s%s✓ All policy checks passed%s\n", colorBold, colorGreen, colorReset)
		resultStatus = "success"
		policyStatus = "pass"
		return nil
	}

	if hasErrors {
		fmt.Printf("\n%s%s✗ Policy check failed%s\n", colorBold, colorRed, colorReset)
		policyStatus = "fail"
		err = fmt.Errorf("policy check failed")
		os.Exit(1)
	} else if hasWarnings {
		// In warn mode, warnings don't cause failure
		if policyConfig.Mode == models.PolicyModeWarn {
			fmt.Printf("\n%s%s⚠ Policy check passed with warnings%s\n", colorBold, colorYellow, colorReset)
			resultStatus = "success"
			policyStatus = "warn"
			return nil
		}
		// In strict mode (default), warnings are errors
		fmt.Printf("\n%s%s✗ Policy check failed (strict mode)%s\n", colorBold, colorRed, colorReset)
		policyStatus = "fail"
		err = fmt.Errorf("policy check failed (strict mode)")
		os.Exit(1)
	}
	return nil
}

// loadPolicyWithPreset loads policy from file or preset
func loadPolicyWithPreset(path string, preset string) (*models.PolicyConfig, error) {
	// Preset takes precedence if specified
	if preset != "" {
		if p := policy.GetPreset(preset); p != nil {
			return p, nil
		}
		return nil, fmt.Errorf("unknown preset: %s (use 'baseline' or 'strict')", preset)
	}

	return loadPolicy(path)
}

// loadPolicy returns policy or default
func loadPolicy(path string) (*models.PolicyConfig, error) {
	if path == "" {
		return &defaultPolicy, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var config models.PolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	if len(config.Rules) == 0 {
		return nil, fmt.Errorf("policy must have at least one rule")
	}

	return &config, nil
}

// extractPolicyCommand parses args
func extractPolicyCommand(args []string) string {
	if len(args) == 0 {
		// Check if command comes from os.Args
		osArgs := os.Args
		dashDashIdx := -1
		for i, arg := range osArgs {
			if arg == "--" {
				dashDashIdx = i
				break
			}
		}
		if dashDashIdx >= 0 && dashDashIdx < len(osArgs)-1 {
			return strings.Join(osArgs[dashDashIdx+1:], " ")
		}
		return ""
	}
	return strings.Join(args, " ")
}
