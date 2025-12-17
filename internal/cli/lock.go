package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/scanner"
	"github.com/spf13/cobra"
)

const (
	defaultLockfilePath = "mcp-lock.json"
)

// colors
const (
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
	colorReset = "\033[0m"
)

// lockCmd
var lockCmd = &cobra.Command{
	Use:   "lock -- <command>",
	Short: "Lock MCP server capabilities to mcp-lock.json",
	Long: `Scans server and creates mcp-lock.json capturing current capabilities.
Facilitates drift detection.

Example:
  mcptrust lock -- "npx -y @modelcontextprotocol/server-filesystem /tmp"`,
	RunE: runLock,
}

var (
	lockTimeoutFlag time.Duration
	lockOutputFlag  string
	lockForceFlag   bool
)

func init() {
	lockCmd.Flags().DurationVarP(&lockTimeoutFlag, "timeout", "t", defaultTimeout, "Timeout for MCP operations")
	lockCmd.Flags().StringVarP(&lockOutputFlag, "output", "o", defaultLockfilePath, "Output path for the lockfile")
	lockCmd.Flags().BoolVarP(&lockForceFlag, "force", "f", false, "Overwrite lockfile even if drift is detected")
}

// GetLockCmd export
func GetLockCmd() *cobra.Command {
	return lockCmd
}

func runLock(cmd *cobra.Command, args []string) error {
	// command after '--'
	command := extractCommand(args)
	if command == "" {
		return fmt.Errorf("no MCP server command provided. Usage: mcptrust lock -- <command>")
	}

	ctx, cancel := context.WithTimeout(context.Background(), lockTimeoutFlag)
	defer cancel()

	fmt.Println("Scanning MCP server...")
	report, err := scanner.Scan(ctx, command, lockTimeoutFlag)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if report.Error != "" {
		return fmt.Errorf("scan error: %s", report.Error)
	}

	manager := locker.NewManager()
	newLockfile, err := manager.CreateLockfile(report)
	if err != nil {
		return fmt.Errorf("failed to create lockfile: %w", err)
	}

	// check for drift
	if manager.Exists(lockOutputFlag) {
		existingLockfile, err := manager.Load(lockOutputFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sWarning: Could not load existing lockfile: %v%s\n", colorRed, err, colorReset)
		} else {
			drifts := manager.DetectDrift(existingLockfile, newLockfile)
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
			} else {
				fmt.Printf("%s✓ No drift detected - lockfile is up to date%s\n", colorGreen, colorReset)
				return nil
			}
		}
	}

	if err := manager.Save(newLockfile, lockOutputFlag); err != nil {
		return fmt.Errorf("failed to save lockfile: %w", err)
	}

	fmt.Printf("%s✓ Lockfile created: %s%s\n", colorGreen, lockOutputFlag, colorReset)
	fmt.Printf("  Locked %d tool(s)\n", len(newLockfile.Tools))

	return nil
}
