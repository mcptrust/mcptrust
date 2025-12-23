package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/policy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// policyExplainCmd outputs policy rules with metadata
var policyExplainCmd = &cobra.Command{
	Use:   "explain",
	Short: "Output policy rules with compliance metadata",
	Long: `Display policy rules with their associated control references, evidence, 
and evidence commands in human-readable Markdown or machine-readable JSON.

Example:
  mcptrust policy explain --preset strict
  mcptrust policy explain --preset baseline --json
  mcptrust policy explain --policy ./my-policy.yaml --output report.md`,
	SilenceUsage: true,
	RunE:         runPolicyExplain,
}

var (
	explainPreset string
	explainPolicy string
	explainJSON   bool
	explainOutput string
)

func init() {
	policyExplainCmd.Flags().StringVar(&explainPreset, "preset", "", "Use built-in preset: baseline or strict")
	policyExplainCmd.Flags().StringVar(&explainPolicy, "policy", "", "Path to policy YAML file")
	policyExplainCmd.Flags().BoolVar(&explainJSON, "json", false, "Output JSON instead of Markdown")
	policyExplainCmd.Flags().StringVar(&explainOutput, "output", "", "Write output to file (default: stdout)")
	policyCmd.AddCommand(policyExplainCmd)
}

// ExplainOutput is the JSON output schema
type ExplainOutput struct {
	SchemaVersion string        `json:"schema_version"`
	Source        ExplainSource `json:"source"`
	GeneratedAt   string        `json:"generated_at"`
	Rules         []ExplainRule `json:"rules"`
}

// ExplainSource identifies where the policy came from
type ExplainSource struct {
	Type string `json:"type"` // "preset" or "file"
	Name string `json:"name"` // preset name or file path
}

// ExplainRule is a rule with all metadata for JSON output
type ExplainRule struct {
	Name             string   `json:"name"`
	Severity         string   `json:"severity"`
	Expr             string   `json:"expr"`
	FailureMsg       string   `json:"failure_msg"`
	ControlRefs      []string `json:"control_refs"`
	Evidence         []string `json:"evidence"`
	EvidenceCommands []string `json:"evidence_commands"`
}

func runPolicyExplain(cmd *cobra.Command, args []string) error {
	// Validate flags
	if explainPreset != "" && explainPolicy != "" {
		return fmt.Errorf("cannot use both --preset and --policy; choose one")
	}

	// Load policy config
	var config *models.PolicyConfig
	var source ExplainSource
	var err error

	if explainPolicy != "" {
		// Load from file
		config, err = loadPolicyFile(explainPolicy)
		if err != nil {
			return err
		}
		source = ExplainSource{Type: "file", Name: explainPolicy}
	} else {
		// Use preset (default to baseline if neither specified)
		presetName := explainPreset
		if presetName == "" {
			presetName = "baseline"
		}
		config = policy.GetPreset(presetName)
		if config == nil {
			return fmt.Errorf("unknown preset: %s (valid: %s)", presetName, strings.Join(policy.ListPresetNames(), ", "))
		}
		source = ExplainSource{Type: "preset", Name: presetName}
	}

	// Generate output
	var output string
	if explainJSON {
		output, err = generateExplainJSON(config, source)
	} else {
		output, err = generateExplainMarkdown(config, source)
	}
	if err != nil {
		return err
	}

	// Write output
	if explainOutput != "" {
		if err := os.WriteFile(explainOutput, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("Output written to %s\n", explainOutput)
		return nil
	}

	fmt.Print(output)
	return nil
}

// loadPolicyFile loads a policy from YAML file
func loadPolicyFile(path string) (*models.PolicyConfig, error) {
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

// generateExplainJSON produces JSON output
func generateExplainJSON(config *models.PolicyConfig, source ExplainSource) (string, error) {
	output := ExplainOutput{
		SchemaVersion: "1.0",
		Source:        source,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Rules:         make([]ExplainRule, 0, len(config.Rules)),
	}

	for _, rule := range config.Rules {
		severity := string(rule.Severity)
		if severity == "" {
			severity = "error"
		}

		// Ensure nil slices become empty arrays in JSON
		controlRefs := rule.ControlRefs
		if controlRefs == nil {
			controlRefs = []string{}
		}
		evidence := rule.Evidence
		if evidence == nil {
			evidence = []string{}
		}
		evidenceCommands := rule.EvidenceCommands
		if evidenceCommands == nil {
			evidenceCommands = []string{}
		}

		output.Rules = append(output.Rules, ExplainRule{
			Name:             rule.Name,
			Severity:         severity,
			Expr:             rule.Expr,
			FailureMsg:       rule.FailureMsg,
			ControlRefs:      controlRefs,
			Evidence:         evidence,
			EvidenceCommands: evidenceCommands,
		})
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(jsonBytes) + "\n", nil
}

// generateExplainMarkdown produces Markdown table output
func generateExplainMarkdown(config *models.PolicyConfig, source ExplainSource) (string, error) {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("# Policy: %s\n\n", config.Name))
	sb.WriteString(fmt.Sprintf("**Source**: %s (`%s`)\n\n", source.Type, source.Name))

	// Table header
	sb.WriteString("| Rule | Severity | Control Refs | Evidence | Evidence Commands | Expr |\n")
	sb.WriteString("|------|----------|--------------|----------|-------------------|------|\n")

	for _, rule := range config.Rules {
		severity := string(rule.Severity)
		if severity == "" {
			severity = "error"
		}

		// Format slice fields
		controlRefs := formatSliceForMD(rule.ControlRefs)
		evidence := formatSliceForMD(rule.Evidence)
		evidenceCommands := formatSliceForMD(rule.EvidenceCommands)

		// Truncate expr for readability
		expr := truncateExpr(rule.Expr, 120)

		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | `%s` |\n",
			rule.Name, severity, controlRefs, evidence, evidenceCommands, expr))
	}

	sb.WriteString("\n")
	return sb.String(), nil
}

// formatSliceForMD formats a string slice for Markdown table cell
func formatSliceForMD(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ", ")
}

// truncateExpr shortens CEL expressions for table display
func truncateExpr(expr string, maxLen int) string {
	// Remove newlines for table display
	expr = strings.ReplaceAll(expr, "\n", " ")
	expr = strings.Join(strings.Fields(expr), " ") // normalize whitespace

	if len(expr) <= maxLen {
		return expr
	}
	return expr[:maxLen-1] + "…"
}
