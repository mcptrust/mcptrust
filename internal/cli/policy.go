package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dtang19/mcptrust/internal/models"
	"github.com/dtang19/mcptrust/internal/policy"
	"github.com/dtang19/mcptrust/internal/scanner"
	"github.com/spf13/cobra"
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

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy management commands",
	Long:  `Manage and enforce security policies against MCP servers.`,
}

var policyCheckCmd = &cobra.Command{
	Use:   "check -- <command>",
	Short: "Check an MCP server against security policies",
	Long: `Check an MCP server's capabilities against security policies defined in a YAML file.

Policies use CEL (Common Expression Language) to define rules that are evaluated
against the scan report. The 'input' variable provides access to the scan data.

Example:
  mcptrust policy check --policy ./policy.yaml -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
  mcptrust policy check -- "python mcp_server.py"`,
	SilenceUsage: true,
	RunE:         runPolicyCheck,
}

var (
	policyFile    string
	policyTimeout time.Duration
)

func init() {
	policyCheckCmd.Flags().StringVarP(&policyFile, "policy", "P", "", "Path to policy YAML file (uses default policy if not provided)")
	policyCheckCmd.Flags().DurationVarP(&policyTimeout, "timeout", "t", 10*time.Second, "Timeout for MCP operations")
	policyCmd.AddCommand(policyCheckCmd)
}

// GetPolicyCmd returns the policy command
func GetPolicyCmd() *cobra.Command {
	return policyCmd
}

func runPolicyCheck(cmd *cobra.Command, args []string) error {
	// command after '--'
	command := extractPolicyCommand(args)
	if command == "" {
		return fmt.Errorf("no MCP server command provided. Usage: mcptrust policy check -- <command>")
	}

	policyConfig, err := loadPolicy(policyFile)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	fmt.Printf("%s%sPolicy:%s %s\n\n", colorBold, colorYellow, colorReset, policyConfig.Name)

	engine, err := policy.NewEngine()
	if err != nil {
		return fmt.Errorf("failed to create policy engine: %w", err)
	}

	if err := engine.CompileAndValidate(policyConfig); err != nil {
		return err
	}

	fmt.Printf("Scanning MCP server...\n\n")
	ctx, cancel := context.WithTimeout(context.Background(), policyTimeout)
	defer cancel()

	report, err := scanner.Scan(ctx, command, policyTimeout)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if report.Error != "" {
		fmt.Printf("%s⚠ Warning:%s Scan completed with errors: %s\n\n", colorYellow, colorReset, report.Error)
	}

	results, err := engine.Evaluate(policyConfig, report)
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}

	fmt.Printf("%s%sResults:%s\n", colorBold, colorYellow, colorReset)
	fmt.Println(strings.Repeat("-", 50))

	allPassed := true
	for _, result := range results {
		if result.Passed {
			fmt.Printf("%s✓%s %s\n", colorGreen, colorReset, result.RuleName)
		} else {
			allPassed = false
			fmt.Printf("%s✗%s %s\n", colorRed, colorReset, result.RuleName)
			fmt.Printf("  %s→ %s%s\n", colorRed, result.FailureMsg, colorReset)
		}
	}

	fmt.Println(strings.Repeat("-", 50))

	if allPassed {
		fmt.Printf("\n%s%s✓ All policy checks passed%s\n", colorBold, colorGreen, colorReset)
		return nil
	}

	fmt.Printf("\n%s%s✗ Some policy checks failed%s\n", colorBold, colorRed, colorReset)
	os.Exit(1)
	return nil
}

// loadPolicy loads a policy from a YAML file or returns the default policy
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

// extractPolicyCommand gets the command string from args
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
