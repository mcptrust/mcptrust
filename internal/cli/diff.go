package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/dtang19/mcptrust/internal/differ"
	"github.com/spf13/cobra"
)

// ANSI color codes
const (
	colorYellow = "\033[33m"
)

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff -- <command>",
	Short: "Compare live MCP server against lockfile",
	Long: `Diff compares the current state of an MCP server against the saved
mcp-lock.json lockfile and reports what has changed.

This is the "Semantic Translator" - it tells you exactly what changed
in human-readable terms, not just raw JSON patches.

The command to start the MCP server should be provided after '--'.

Example:
  mcptrust diff -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
  mcptrust diff -- "python mcp_server.py"`,
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

// GetDiffCmd returns the diff command
func GetDiffCmd() *cobra.Command {
	return diffCmd
}

func runDiff(cmd *cobra.Command, args []string) error {
	// command after '--'
	command := extractCommand(args)
	if command == "" {
		fmt.Fprintf(os.Stderr, "Error: no MCP server command provided. Usage: mcptrust diff -- <command>\n")
		os.Exit(2) // Exit 2 = runtime/usage error
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), diffTimeoutFlag)
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
		return nil
	}

	// Print header for changes
	fmt.Printf("\n%s╔══════════════════════════════════════╗%s\n", colorYellow, colorReset)
	fmt.Printf("%s║         CHANGES DETECTED             ║%s\n", colorYellow, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════╝%s\n\n", colorYellow, colorReset)

	for _, toolDiff := range result.ToolDiffs {
		printToolDiff(toolDiff)
	}

	// Exit 1 = drift detected (changes found)
	os.Exit(1)
	return nil
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
