package cli

import (
	"fmt"
	"os"

	"github.com/mcptrust/mcptrust/internal/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mcptrust",
	Short: "Security scanner for MCP servers",
	Long: `mcptrust is the "lockfile for the Agentic Web."

It secures AI agents by verifying Model Context Protocol (MCP) servers
before they are used. mcptrust interrogates MCP servers for their
capabilities and analyzes them for security risks.`,
	Version: version.BuildVersion(),
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(GetScanCmd())
	rootCmd.AddCommand(GetLockCmd())
	rootCmd.AddCommand(GetDiffCmd())
	rootCmd.AddCommand(GetPolicyCmd())
	rootCmd.AddCommand(GetKeygenCmd())
	rootCmd.AddCommand(GetSignCmd())
	rootCmd.AddCommand(GetVerifyCmd())
	rootCmd.AddCommand(GetBundleCmd())
}
