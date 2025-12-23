package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/observability"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	otelobs "github.com/mcptrust/mcptrust/internal/observability/otel"
	"github.com/mcptrust/mcptrust/internal/scanner"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultTimeout = 10 * time.Second
)

// scanCmd definition
var scanCmd = &cobra.Command{
	Use:   "scan -- <command>",
	Short: "Scan MCP server risks",
	Long: `Connects to server, interrogates capabilities, outputs JSON report.

Example:
  mcptrust scan -- "npx -y @modelcontextprotocol/server-filesystem /tmp"`,
	RunE: runScan,
}

var (
	timeoutFlag time.Duration
	prettyFlag  bool
)

func init() {
	scanCmd.Flags().DurationVarP(&timeoutFlag, "timeout", "t", defaultTimeout, "Timeout for MCP operations")
	scanCmd.Flags().BoolVarP(&prettyFlag, "pretty", "p", false, "Pretty print JSON output")
}

// GetScanCmd exports the scan command
func GetScanCmd() *cobra.Command {
	return scanCmd
}

func runScan(cmd *cobra.Command, args []string) (err error) {
	// command after '--'
	command := extractCommand(args)
	if command == "" {
		return fmt.Errorf("no MCP server command provided. Usage: mcptrust scan -- <command>")
	}

	// Get logger
	ctx := cmd.Context()
	log := logging.From(ctx)
	start := time.Now()

	// Start OTel span if enabled (before log.Event so trace_id is available)
	if h := otelobs.From(ctx); h != nil {
		var span trace.Span
		ctx, span = h.Tracer.Start(ctx, "mcptrust.scan",
			trace.WithAttributes(
				attribute.String("mcptrust.op_id", observability.OpID(ctx)),
				attribute.String("mcptrust.command", "scan"),
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
	log.Event(ctx, "scan.start", nil)

	var resultStatus string
	defer func() {
		log.Event(ctx, "scan.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
	}()

	ctx, cancel := context.WithTimeout(ctx, timeoutFlag)
	defer cancel()

	report, scanErr := scanner.Scan(ctx, command, timeoutFlag)
	if scanErr != nil {
		resultStatus = "fail"
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	// dump json
	var output []byte
	if prettyFlag {
		output, err = json.MarshalIndent(report, "", "  ")
	} else {
		output, err = json.Marshal(report)
	}
	if err != nil {
		resultStatus = "fail"
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	fmt.Println(string(output))
	resultStatus = "success"
	return nil
}

// extractCommand helper
func extractCommand(args []string) string {
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
