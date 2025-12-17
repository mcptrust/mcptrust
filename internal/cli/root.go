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
	Long: `mcptrust: lockfile for the Agentic Web.
Secures AI agents by verifying MCP servers before use.`,
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
