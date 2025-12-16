package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dtang19/mcptrust/internal/scanner"
	"github.com/spf13/cobra"
)

const (
	defaultTimeout = 10 * time.Second
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan -- <command>",
	Short: "Scan an MCP server for security risks",
	Long: `Scan connects to an MCP server, interrogates it for capabilities,
and outputs a security report in JSON format.

The command to start the MCP server should be provided after '--'.

Example:
  mcptrust scan -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
  mcptrust scan -- "python mcp_server.py"`,
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

func runScan(cmd *cobra.Command, args []string) error {
	// command after '--'
	command := extractCommand(args)
	if command == "" {
		return fmt.Errorf("no MCP server command provided. Usage: mcptrust scan -- <command>")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag)
	defer cancel()

	report, err := scanner.Scan(ctx, command, timeoutFlag)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// dump json
	var output []byte
	if prettyFlag {
		output, err = json.MarshalIndent(report, "", "  ")
	} else {
		output, err = json.Marshal(report)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

// extractCommand handles the double dash args dance
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
