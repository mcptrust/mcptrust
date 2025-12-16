package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time
var Version = "dev"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mcptrust",
	Short: "Security scanner for MCP servers",
	Long: `mcptrust is the "lockfile for the Agentic Web."

It secures AI agents by verifying Model Context Protocol (MCP) servers
before they are used. mcptrust interrogates MCP servers for their
capabilities and analyzes them for security risks.`,
	Version: Version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Add commands
	rootCmd.AddCommand(GetScanCmd())
	rootCmd.AddCommand(GetLockCmd())
	rootCmd.AddCommand(GetDiffCmd())
	rootCmd.AddCommand(GetPolicyCmd())
	rootCmd.AddCommand(GetKeygenCmd())
	rootCmd.AddCommand(GetSignCmd())
	rootCmd.AddCommand(GetVerifyCmd())
	rootCmd.AddCommand(GetBundleCmd())
}
