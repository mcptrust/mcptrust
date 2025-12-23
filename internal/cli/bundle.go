package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/bundler"
	"github.com/mcptrust/mcptrust/internal/crypto"
	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	"github.com/spf13/cobra"
)

const (
	defaultOutputPath = "approval.zip"
)

// bundleCmd group
var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Bundle security artifacts for distribution",
	Long:  `Package signed mcp-lock.json and artifacts into a single ZIP.`,
}

// bundleExportCmd
var bundleExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export to reproducible ZIP",
	Long: `Export signed lockfile and artifacts.
Contents: manifest.json, mcp-lock.json, signatures, policy.
Deterministic output.`,
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

// GetBundleCmd export
func GetBundleCmd() *cobra.Command {
	return bundleCmd
}

func runBundleExport(cmd *cobra.Command, args []string) error {
	// Get logger and emit start event
	ctx := cmd.Context()
	log := logging.From(ctx)
	start := time.Now()
	log.Event(ctx, "bundle_export.start", nil)

	var resultStatus string
	defer func() {
		log.Event(ctx, "bundle_export.complete", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"result":      resultStatus,
		})
	}()

	// check required files
	if _, err := os.Stat(bundleLockfileFlag); err != nil {
		resultStatus = "fail"
		return fmt.Errorf("lockfile not found at %s: you must run 'mcptrust lock' first", bundleLockfileFlag)
	}

	if _, err := os.Stat(bundleSignatureFlag); err != nil {
		resultStatus = "fail"
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

	resultStatus = "success"
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
