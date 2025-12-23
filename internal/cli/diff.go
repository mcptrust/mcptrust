package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mcptrust/mcptrust/internal/differ"
	"github.com/mcptrust/mcptrust/internal/observability"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	otelobs "github.com/mcptrust/mcptrust/internal/observability/otel"
	"github.com/mcptrust/mcptrust/internal/observability/receipt"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// diffCmd
var diffCmd = &cobra.Command{
	Use:   "diff -- <command>",
	Short: "Compare live server vs lockfile",
	Long: `Compares current server state against mcp-lock.json.
Reports what changed in human-readable terms.`,
	SilenceUsage: true,
	RunE:         runDiff,
}

var (
	diffTimeoutFlag  time.Duration
	diffLockfileFlag string
)

func init() {
	diffCmd.Flags().DurationVarP(&diffTimeoutFlag, "timeout", "t", defaultTimeout, "Timeout for MCP operations")
	diffCmd.Flags().StringVarP(&diffLockfileFlag, "lockfile", "l", defaultLockfilePath, "Path to the lockfile")
}

// GetDiffCmd export
func GetDiffCmd() *cobra.Command {
	return diffCmd
}

func runDiff(cmd *cobra.Command, args []string) (err error) {
	// Get context and start receipt session immediately for early-return coverage
	ctx := cmd.Context()
	sess := receipt.Start(ctx, "mcptrust diff", os.Args[1:])
	var criticalCount, benignCount int
	var driftSummary string

	defer func() {
		_ = sess.Finish(err, receipt.WithDrift(criticalCount, benignCount, driftSummary))
	}()

	// command after '--'
	command := extractCommand(args)
	if command == "" {
		fmt.Fprintf(os.Stderr, "Error: no MCP server command provided. Usage: mcptrust diff -- <command>\n")
		err = fmt.Errorf("no MCP server command provided")
		os.Exit(2) // Exit 2 = runtime/usage error
		return
	}

	// Get logger
	log := logging.From(ctx)
	start := time.Now()

	// Start OTel span if enabled (before log.Event so trace_id is available)
	if h := otelobs.From(ctx); h != nil {
		var span trace.Span
		ctx, span = h.Tracer.Start(ctx, "mcptrust.diff",
			trace.WithAttributes(
				attribute.String("mcptrust.op_id", observability.OpID(ctx)),
				attribute.String("mcptrust.command", "diff"),
				attribute.String("mcptrust.lockfile", diffLockfileFlag),
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
	log.Event(ctx, "diff.start", nil)

	var resultStatus string
	defer func() {
		log.Event(ctx, "diff.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
	}()

	ctx, cancel := context.WithTimeout(ctx, diffTimeoutFlag)
	defer cancel()

	engine := differ.NewEngine(diffTimeoutFlag)

	fmt.Println("Scanning MCP server and comparing against lockfile...")
	result, err := engine.ComputeDiff(ctx, diffLockfileFlag, command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: diff failed: %v\n", err)
		os.Exit(1) // Exit 1 = runtime error (scan failure, parse error, etc.)
		return nil
	}

	// Exit 0 = no drift (server matches lockfile)
	if !result.HasChanges {
		fmt.Printf("%s✓ No changes detected - server matches lockfile%s\n", colorGreen, colorReset)
		resultStatus = "success"
		driftSummary = "no changes"
		return nil
	}

	// Print header for changes
	fmt.Printf("\n%s╔══════════════════════════════════════╗%s\n", colorYellow, colorReset)
	fmt.Printf("%s║         CHANGES DETECTED             ║%s\n", colorYellow, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════╝%s\n\n", colorYellow, colorReset)

	for _, toolDiff := range result.ToolDiffs {
		printToolDiff(toolDiff)
		// Count severity
		for _, tr := range toolDiff.Translations {
			sev := differ.GetSeverity(tr)
			if sev == differ.SeverityCritical {
				criticalCount++
			} else {
				benignCount++
			}
		}
	}

	driftSummary = fmt.Sprintf("%d tool(s) changed", len(result.ToolDiffs))

	// Exit 1 = drift detected (changes found)
	resultStatus = "fail"
	err = fmt.Errorf("drift detected: %d tool(s) changed", len(result.ToolDiffs))
	os.Exit(1)
	return
}

func printToolDiff(td differ.ToolDiff) {
	var headerColor string
	var icon string

	switch td.DiffType {
	case differ.DiffTypeAdded:
		headerColor = colorYellow
		icon = "+"
	case differ.DiffTypeRemoved:
		headerColor = colorRed
		icon = "-"
	case differ.DiffTypeChanged:
		headerColor = colorYellow
		icon = "~"
	default:
		headerColor = colorReset
		icon = " "
	}

	fmt.Printf("%s[%s] %s%s\n", headerColor, icon, td.ToolName, colorReset)

	// Print each translation with appropriate color
	for _, translation := range td.Translations {
		severity := differ.GetSeverity(translation)
		color := getColorForSeverity(severity)
		fmt.Printf("  %s• %s%s\n", color, translation, colorReset)
	}

	fmt.Println()
}

func getColorForSeverity(severity differ.SeverityLevel) string {
	switch severity {
	case differ.SeverityCritical:
		return colorRed
	case differ.SeverityModerate:
		return colorYellow
	case differ.SeveritySafe:
		return colorGreen
	default:
		return colorReset
	}
}
