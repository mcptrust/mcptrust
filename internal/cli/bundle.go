package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mcptrust/mcptrust/internal/bundler"
	"github.com/mcptrust/mcptrust/internal/crypto"
	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/spf13/cobra"
)

const (
	defaultOutputPath = "approval.zip"
)

// bundleCmd represents the bundle command group
var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Bundle security artifacts for distribution",
	Long: `Bundle security artifacts into a distributable package.

The bundle command packages your signed mcp-lock.json and related
artifacts into a single ZIP file for production or compliance use.`,
}

// bundleExportCmd represents the bundle export subcommand
var bundleExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export security artifacts to a deterministic ZIP file",
	Long: `Export the signed lockfile and security artifacts to a deterministic ZIP bundle.

This creates a reproducible bundle containing:
  - manifest.json (Bundle metadata with file hashes)
  - mcp-lock.json (Required - lockfile)
  - mcp-lock.json.sig (Required - signature)
  - public.key (Optional, if present)
  - policy.yaml (Optional, if present)
  - README.txt (Generated list of approved tools)

The bundle is fully deterministic - identical inputs produce identical outputs.
The lockfile must be signed before bundling. Use 'mcptrust sign' first.

Example:
  mcptrust bundle export --output approval.zip
  mcptrust bundle export -o release-artifacts.zip`,
	RunE: runBundleExport,
}

var (
	bundleOutputFlag    string
	bundleLockfileFlag  string
	bundleSignatureFlag string
)

func init() {
	bundleExportCmd.Flags().StringVarP(&bundleOutputFlag, "output", "o", defaultOutputPath, "Path for the output ZIP file")
	bundleExportCmd.Flags().StringVarP(&bundleLockfileFlag, "lockfile", "l", defaultLockfilePath, "Path to the lockfile")
	bundleExportCmd.Flags().StringVarP(&bundleSignatureFlag, "signature", "s", defaultSignaturePath, "Path to the signature file")

	bundleCmd.AddCommand(bundleExportCmd)
}

// GetBundleCmd returns the bundle command group
func GetBundleCmd() *cobra.Command {
	return bundleCmd
}

func runBundleExport(cmd *cobra.Command, args []string) error {
	// check required files
	if _, err := os.Stat(bundleLockfileFlag); err != nil {
		return fmt.Errorf("lockfile not found at %s: you must run 'mcptrust lock' first", bundleLockfileFlag)
	}

	if _, err := os.Stat(bundleSignatureFlag); err != nil {
		return fmt.Errorf("signature not found at %s: you must run 'mcptrust sign' first (cannot bundle unsigned code)", bundleSignatureFlag)
	}

	// load lockfile for readme
	lockfileData, err := os.ReadFile(bundleLockfileFlag)
	if err != nil {
		return fmt.Errorf("failed to read lockfile: %w", err)
	}

	var lockfile models.Lockfile
	if err := json.Unmarshal(lockfileData, &lockfile); err != nil {
		return fmt.Errorf("failed to parse lockfile: %w", err)
	}

	// read signature to get canonicalization version
	sigData, err := os.ReadFile(bundleSignatureFlag)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}
	envelope, err := crypto.ReadSignature(sigData)
	if err != nil {
		return fmt.Errorf("invalid signature file: %w", err)
	}
	canonVersion := envelope.GetCanonVersion()

	readmeContent := generateReadmeContent(lockfile)

	opts := bundler.BundleOptions{
		LockfilePath:  bundleLockfileFlag,
		SignaturePath: bundleSignatureFlag,
		PublicKeyPath: defaultPublicKeyPath,
		PolicyPath:    "policy.yaml",
		OutputPath:    bundleOutputFlag,
	}

	// generate manifest
	manifest, err := bundler.GenerateManifest(opts, canonVersion)
	if err != nil {
		return fmt.Errorf("failed to generate manifest: %w", err)
	}

	fmt.Printf("Creating security bundle...\n")
	if err := bundler.CreateBundle(opts, readmeContent, manifest); err != nil {
		return fmt.Errorf("bundle creation failed: %w", err)
	}

	fmt.Printf("%s✓ Bundle created: %s%s\n", colorGreen, bundleOutputFlag, colorReset)

	fmt.Printf("\nBundle contents:\n")
	fmt.Printf("  • manifest.json (bundle metadata)\n")
	fmt.Printf("  • mcp-lock.json (lockfile)\n")
	fmt.Printf("  • mcp-lock.json.sig (signature)\n")

	if _, err := os.Stat(defaultPublicKeyPath); err == nil {
		fmt.Printf("  • public.key (verification key)\n")
	}

	if _, err := os.Stat("policy.yaml"); err == nil {
		fmt.Printf("  • policy.yaml (security policy)\n")
	}

	fmt.Printf("  • README.txt (tool manifest)\n")

	return nil
}

func generateReadmeContent(lockfile models.Lockfile) string {
	var sb strings.Builder

	sb.WriteString("MCPTrust Security Bundle\n")
	sb.WriteString("========================\n\n")
	sb.WriteString(fmt.Sprintf("Server Command: %s\n", lockfile.ServerCommand))
	sb.WriteString(fmt.Sprintf("Lockfile Version: %s\n\n", lockfile.Version))

	sb.WriteString("Approved Tools\n")
	sb.WriteString("--------------\n\n")

	// sort tools
	toolNames := make([]string, 0, len(lockfile.Tools))
	for name := range lockfile.Tools {
		toolNames = append(toolNames, name)
	}
	sort.Strings(toolNames)

	// group by risk
	riskGroups := map[models.RiskLevel][]string{
		models.RiskLevelHigh:   {},
		models.RiskLevelMedium: {},
		models.RiskLevelLow:    {},
	}

	for _, name := range toolNames {
		tool := lockfile.Tools[name]
		riskGroups[tool.RiskLevel] = append(riskGroups[tool.RiskLevel], name)
	}

	// high risk first
	if len(riskGroups[models.RiskLevelHigh]) > 0 {
		sb.WriteString("[HIGH RISK]\n")
		for _, name := range riskGroups[models.RiskLevelHigh] {
			sb.WriteString(fmt.Sprintf("  - %s\n", name))
		}
		sb.WriteString("\n")
	}

	if len(riskGroups[models.RiskLevelMedium]) > 0 {
		sb.WriteString("[MEDIUM RISK]\n")
		for _, name := range riskGroups[models.RiskLevelMedium] {
			sb.WriteString(fmt.Sprintf("  - %s\n", name))
		}
		sb.WriteString("\n")
	}

	if len(riskGroups[models.RiskLevelLow]) > 0 {
		sb.WriteString("[LOW RISK]\n")
		for _, name := range riskGroups[models.RiskLevelLow] {
			sb.WriteString(fmt.Sprintf("  - %s\n", name))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("Total Tools: %d\n", len(lockfile.Tools)))

	return sb.String()
}
