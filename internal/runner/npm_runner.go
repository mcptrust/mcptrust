package runner

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/artifact"
	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/netutil"
)

type NPMRunner struct{}

func (r *NPMRunner) Run(ctx context.Context, config *RunConfig) (*RunResult, error) {
	lockfile := config.Lockfile
	pin := lockfile.Artifact

	if pin == nil {
		return nil, fmt.Errorf("lockfile has no artifact pin; run 'mcptrust lock --pin' first")
	}

	if pin.Type != models.ArtifactTypeNPM {
		return nil, fmt.Errorf("artifact type %q is not npm", pin.Type)
	}

	if pin.Integrity == "" {
		return nil, fmt.Errorf("artifact has no integrity hash; cannot verify")
	}

	if config.CommandOverride != "" {
		if err := ValidateArtifactMatch(pin.Name, pin.Version, config.CommandOverride); err != nil {
			return nil, fmt.Errorf("command override mismatch: %w", err)
		}
	}

	result := &RunResult{
		ExitCode: -1,
	}

	tempDir, err := createSecureTempDir("mcptrust-npm-run-*")
	if err != nil {
		return nil, err
	}
	result.TempDir = tempDir

	if !config.KeepTemp {
		defer os.RemoveAll(tempDir)
	}

	if err := writeMinimalPackageJSON(tempDir); err != nil {
		return nil, fmt.Errorf("failed to write package.json: %w", err)
	}

	tarballURL := pin.TarballURL
	usedFallbackURL := false
	if tarballURL == "" {
		var err error
		tarballURL, err = r.resolveTarballURL(ctx, pin)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve tarball URL: %w", err)
		}
	}

	if err := netutil.ValidateTarballURL(tarballURL, config.AllowPrivateTarballHosts); err != nil {
		return nil, fmt.Errorf("invalid tarball URL: %w", err)
	}

	tarballPath := filepath.Join(tempDir, "package.tgz")
	computedSHA256, err := r.downloadTarballWithSHA256(ctx, tarballURL, tarballPath, config.AllowPrivateTarballHosts)

	if err != nil && pin.TarballURL != "" {
		fmt.Fprintf(os.Stderr, "⚠ Pinned tarball URL failed (%v), trying registry fallback...\n", err)

		fallbackURL, resolveErr := r.resolveTarballURL(ctx, pin)
		if resolveErr == nil && fallbackURL != tarballURL {
			if validateErr := netutil.ValidateTarballURL(fallbackURL, config.AllowPrivateTarballHosts); validateErr == nil {
				computedSHA256, err = r.downloadTarballWithSHA256(ctx, fallbackURL, tarballPath, config.AllowPrivateTarballHosts)
				if err == nil {
					usedFallbackURL = true
					fmt.Fprintf(os.Stderr, "✓ Fallback succeeded (hashes will still be verified)\n")
				}
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to download tarball: %w", err)
	}
	_ = usedFallbackURL // may be used for audit trail in future

	if err := r.verifyIntegrity(tarballPath, pin.Integrity); err != nil {
		return nil, fmt.Errorf("integrity verification failed: %w", err)
	}

	if pin.TarballSHA256 != "" {
		if err := VerifySHA256Match(pin.TarballSHA256, computedSHA256, "pinned vs computed tarball"); err != nil {
			return nil, err
		}
	}

	computedSRI, err := ComputeTarballSRI(tarballPath)
	if err != nil {
		return nil, fmt.Errorf("calc tarball integrity failed: %w", err)
	}

	result.PinnedIntegrity = pin.Integrity
	result.ComputedTarballSRI = computedSRI
	result.ComputedTarballSHA256 = computedSHA256

	if err := VerifyIntegrityMatch(pin.Integrity, computedSRI, "pinned vs computed tarball"); err != nil {
		return nil, err
	}
	result.IntegrityVerified = true

	if err := r.installFromTarball(ctx, tempDir, tarballPath); err != nil {
		return nil, fmt.Errorf("failed to install from tarball: %w", err)
	}

	packageLockPath := filepath.Join(tempDir, "package-lock.json")
	if _, err := os.Stat(packageLockPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("npm install did not create package-lock.json; cannot verify installed artifact")
	}

	resolved, err := InstalledResolvedFromPackageLock(packageLockPath, pin.Name, pin.Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: cannot extract resolved from lockfile: %v\n", err)
	} else if err := ValidateLocalTarballResolved(resolved, tarballPath); err != nil {
		return nil, fmt.Errorf("installed package not from verified tarball: %w", err)
	}
	result.ResolvedSource = resolved

	nodeModulesPath := filepath.Join(tempDir, "node_modules")
	if err := ValidateInstalledPackageIdentity(nodeModulesPath, pin.Name, pin.Version); err != nil {
		return nil, fmt.Errorf("installed package identity mismatch: %w", err)
	}

	installedSRI, err := InstalledIntegrityFromPackageLock(packageLockPath, pin.Name, pin.Version)
	if err != nil || installedSRI == "" {
		if config.AllowMissingInstalledIntegrity {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "╔══════════════════════════════════════════════════════════════════╗\n")
			fmt.Fprintf(os.Stderr, "║  ⚠️  SECURITY GUARANTEE WEAKENED                                  ║\n")
			fmt.Fprintf(os.Stderr, "╠══════════════════════════════════════════════════════════════════╣\n")
			fmt.Fprintf(os.Stderr, "║  Cannot verify installed integrity == pinned integrity           ║\n")
			fmt.Fprintf(os.Stderr, "║  Proceeding due to --allow-missing-installed-integrity flag      ║\n")
			fmt.Fprintf(os.Stderr, "║                                                                   ║\n")
			fmt.Fprintf(os.Stderr, "║  Use only for debugging. Not recommended for production.         ║\n")
			fmt.Fprintf(os.Stderr, "╚══════════════════════════════════════════════════════════════════╝\n")
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Reason: %v\n\n", err)
			}
		} else {
			if err != nil {
				return nil, fmt.Errorf("installed integrity verification failed: %w\n"+
					"  Hint: use --allow-missing-installed-integrity to bypass (NOT recommended)", err)
			}
			return nil, fmt.Errorf("no integrity hash in package-lock.json\n" +
				"  Hint: use --allow-missing-installed-integrity to bypass (not recommended)")
		}
	} else {
		if err := VerifyIntegrityMatch(pin.Integrity, installedSRI, "pinned vs installed"); err != nil {
			return nil, err
		}
		result.InstalledIntegrity = installedSRI
	}

	if config.RequireProvenance {
		if err := r.verifyProvenance(ctx, pin, config.ExpectedSource); err != nil {
			return nil, fmt.Errorf("provenance verification failed: %w", err)
		}
		result.ProvenanceVerified = true
		if pin.Provenance != nil {
			result.ProvenanceInfo = pin.Provenance
		}
	}

	binPath, err := r.resolveBinPath(tempDir, pin.Name, config.BinName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve binary: %w", err)
	}
	result.ExecPath = binPath

	serverCmd := lockfile.ServerCommand
	if config.CommandOverride != "" {
		serverCmd = config.CommandOverride
	}

	execArgs, err := ExtractNPXArgs(serverCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to extract command args: %w", err)
	}
	result.Args = execArgs

	printExecutionReceipt(result, config.DryRun)

	if config.DryRun {
		fmt.Printf("✓ Would execute: %s %s\n", binPath, strings.Join(execArgs, " "))
		result.ExitCode = 0
		return result, nil
	}

	exitCode, err := execCommand(ctx, binPath, execArgs, "", nil)
	if err != nil {
		return nil, fmt.Errorf("execution failed: %w", err)
	}
	result.ExitCode = exitCode

	return result, nil
}

func printExecutionReceipt(result *RunResult, dryRun bool) {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "═══════════════════════════════════════════════════════════════════\n")
	if dryRun {
		fmt.Fprintf(os.Stderr, "  Verification Receipt (dry-run)\n")
	} else {
		fmt.Fprintf(os.Stderr, "  Execution Receipt\n")
	}
	fmt.Fprintf(os.Stderr, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(os.Stderr, "  ✓ Integrity verified\n")
	fmt.Fprintf(os.Stderr, "    Pinned:    %s\n", truncateSRI(result.PinnedIntegrity))
	fmt.Fprintf(os.Stderr, "    Computed:  %s\n", truncateSRI(result.ComputedTarballSRI))
	if result.ComputedTarballSHA256 != "" {
		fmt.Fprintf(os.Stderr, "    SHA256:    %s\n", truncateHash(result.ComputedTarballSHA256, 24))
	}
	if result.InstalledIntegrity != "" {
		fmt.Fprintf(os.Stderr, "    Installed: %s\n", truncateSRI(result.InstalledIntegrity))
	}
	if result.ResolvedSource != "" {
		fmt.Fprintf(os.Stderr, "    Resolved:  %s\n", result.ResolvedSource)
	}
	printProvenanceReceipt(result.ProvenanceInfo, result.ProvenanceVerified)
	fmt.Fprintf(os.Stderr, "═══════════════════════════════════════════════════════════════════\n\n")
}

func printProvenanceReceipt(prov *models.ProvenanceInfo, provenanceRequested bool) {
	FormatProvenanceReceipt(os.Stderr, prov, provenanceRequested)
}

func FormatProvenanceReceipt(w io.Writer, prov *models.ProvenanceInfo, provenanceRequested bool) {
	if !provenanceRequested {
		return
	}

	if prov == nil {
		fmt.Fprintf(w, "  ℹ Provenance not verified\n")
		return
	}

	switch prov.Method {
	case models.ProvenanceMethodCosignSLSA:
		fmt.Fprintf(w, "  ✓ SLSA provenance verified (cosign)\n")
		if prov.PredicateType != "" {
			fmt.Fprintf(w, "    Predicate: %s\n", prov.PredicateType)
		}
		if prov.SourceRepo != "" {
			fmt.Fprintf(w, "    Source:    %s\n", prov.SourceRepo)
		}
		if prov.WorkflowURI != "" {
			fmt.Fprintf(w, "    Workflow:  %s\n", prov.WorkflowURI)
		}
		if prov.BuilderID != "" {
			fmt.Fprintf(w, "    Builder:   %s\n", truncateHash(prov.BuilderID, 50))
		}
	case models.ProvenanceMethodNPMAuditSigs:
		fmt.Fprintf(w, "  ✓ Package signature verified (npm audit signatures)\n")
		fmt.Fprintf(w, "    Note: SLSA metadata unavailable with npm fallback\n")
	default:
		fmt.Fprintf(w, "  ℹ Provenance not verified\n")
	}
}

func truncateSRI(sri string) string {
	if len(sri) <= 30 {
		return sri
	}
	parts := strings.SplitN(sri, "-", 2)
	if len(parts) != 2 {
		return sri
	}
	digest := parts[1]
	if len(digest) <= 24 {
		return sri
	}
	return fmt.Sprintf("%s-%s...%s", parts[0], digest[:12], digest[len(digest)-12:])
}

func truncateHash(hash string, maxLen int) string {
	if len(hash) <= maxLen {
		return hash
	}
	half := maxLen / 2
	return fmt.Sprintf("%s...%s", hash[:half], hash[len(hash)-half:])
}

func (r *NPMRunner) resolveTarballURL(ctx context.Context, pin *models.ArtifactPin) (string, error) {
	registry := pin.Registry
	if registry == "" {
		registry = artifact.DefaultNPMRegistry
	}

	encodedName := url.PathEscape(pin.Name)
	metaURL := fmt.Sprintf("%s/%s/%s", strings.TrimSuffix(registry, "/"), encodedName, pin.Version)

	if err := netutil.ValidateTarballURL(metaURL, false); err != nil {
		return "", fmt.Errorf("registry URL validation failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", metaURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	client := netutil.NewSecureAPIClient(30*time.Second, false)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("registry returned %d: %s", resp.StatusCode, string(body))
	}

	var versionData struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&versionData); err != nil {
		return "", fmt.Errorf("failed to parse registry response: %w", err)
	}

	if versionData.Dist.Tarball == "" {
		return "", fmt.Errorf("no tarball URL in registry response")
	}

	return versionData.Dist.Tarball, nil
}

func (r *NPMRunner) downloadTarballWithSHA256(ctx context.Context, tarballURL, destPath string, allowPrivate bool) (string, error) {
	config := netutil.DefaultConfig()
	config.AllowPrivateHosts = allowPrivate

	result, err := netutil.DownloadTarball(ctx, tarballURL, config)
	if err != nil {
		return "", err
	}
	defer result.Cleanup()

	if err := os.Rename(result.Path, destPath); err != nil {
		src, err := os.Open(result.Path)
		if err != nil {
			return "", fmt.Errorf("failed to open downloaded tarball: %w", err)
		}
		defer src.Close()

		dst, err := os.Create(destPath)
		if err != nil {
			return "", fmt.Errorf("failed to create destination file: %w", err)
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			return "", fmt.Errorf("failed to copy tarball to destination: %w", err)
		}
	}

	return result.SHA256, nil
}

func (r *NPMRunner) verifyIntegrity(tarballPath, expectedSRI string) error {
	parts := strings.SplitN(expectedSRI, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid SRI format: %s", expectedSRI)
	}

	algorithm := strings.ToLower(parts[0])
	expectedHash := parts[1]

	f, err := os.Open(tarballPath)
	if err != nil {
		return err
	}
	defer f.Close()

	var actualHash string
	switch algorithm {
	case "sha512":
		h := sha512.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		actualHash = base64.StdEncoding.EncodeToString(h.Sum(nil))
	default:
		return fmt.Errorf("unsupported SRI algorithm: %s (npm typically uses sha512)", algorithm)
	}

	if actualHash != expectedHash {
		return fmt.Errorf("integrity mismatch:\n  expected: %s-%s\n  got:      %s-%s",
			algorithm, expectedHash, algorithm, actualHash)
	}

	return nil
}

func (r *NPMRunner) verifyProvenance(ctx context.Context, pin *models.ArtifactPin, expectedSource string) error {
	if pin.Provenance != nil && pin.Provenance.Method == models.ProvenanceMethodCosignSLSA {
		if expectedSource != "" && pin.Provenance.SourceRepo != "" {
			matched, err := matchPattern(expectedSource, pin.Provenance.SourceRepo)
			if err != nil {
				return fmt.Errorf("invalid expected source pattern: %w", err)
			}
			if !matched {
				return fmt.Errorf("source repo %q does not match expected %q",
					pin.Provenance.SourceRepo, expectedSource)
			}
		}
		return nil
	}

	if pin.Provenance != nil && pin.Provenance.Method == models.ProvenanceMethodNPMAuditSigs {
		return fmt.Errorf("SLSA provenance required; npm audit signatures are not sufficient. " +
			"Package has npm registry signatures but lacks cosign-verified SLSA attestations. " +
			"Use --require-provenance=false to proceed with signature-only verification")
	}

	result, err := artifact.VerifyNPMProvenance(ctx, pin, expectedSource)
	if err != nil {
		return err
	}

	if result != nil && result.ProvenanceInfo != nil &&
		result.ProvenanceInfo.Method == models.ProvenanceMethodNPMAuditSigs {
		return fmt.Errorf("SLSA provenance required; npm audit signatures are not sufficient. " +
			"Package has npm registry signatures but lacks cosign-verified SLSA attestations. " +
			"Use --require-provenance=false to proceed with signature-only verification")
	}

	return nil
}

func matchPattern(pattern, s string) (bool, error) {
	if !strings.ContainsAny(pattern, ".*+?^${}[]|()\\") {
		return strings.Contains(s, pattern), nil
	}
	return strings.Contains(s, strings.ReplaceAll(pattern, ".*", "")), nil
}

func (r *NPMRunner) installFromTarball(ctx context.Context, dir, tarballPath string) error {
	args := []string{
		"install",
		"--ignore-scripts",
		"--no-fund",
		"--no-audit",
		"--package-lock",
		tarballPath,
	}

	cmd := exec.CommandContext(ctx, "npm", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"npm_config_ignore_scripts=true",
		"npm_config_package_lock=true",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm install failed: %s - %w", string(output), err)
	}

	return nil
}

func (r *NPMRunner) resolveBinPath(tempDir, packageName, binName string) (string, error) {
	unscopedName := extractUnscopedName(packageName)

	pkgDir := filepath.Join(tempDir, "node_modules", packageName)
	pkgJSONPath := filepath.Join(pkgDir, "package.json")

	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return "", fmt.Errorf("failed to read installed package.json: %w", err)
	}

	var pkgJSON struct {
		Bin json.RawMessage `json:"bin"`
	}
	if err := json.Unmarshal(data, &pkgJSON); err != nil {
		return "", fmt.Errorf("failed to parse package.json: %w", err)
	}

	if len(pkgJSON.Bin) == 0 {
		return "", fmt.Errorf("package has no bin field; cannot execute")
	}

	var binPath string
	if err := json.Unmarshal(pkgJSON.Bin, &binPath); err == nil {
		resolvedBin := unscopedName
		if binName != "" && binName != unscopedName {
			return "", fmt.Errorf("package exports single binary %q, but --bin %q requested",
				unscopedName, binName)
		}
		binExecPath := filepath.Join(tempDir, "node_modules", ".bin", resolvedBin)
		if _, err := os.Stat(binExecPath); err == nil {
			return binExecPath, nil
		}
		return filepath.Join(pkgDir, binPath), nil
	}

	var binMap map[string]string
	if err := json.Unmarshal(pkgJSON.Bin, &binMap); err != nil {
		return "", fmt.Errorf("failed to parse bin field: %w", err)
	}

	if len(binMap) == 0 {
		return "", fmt.Errorf("package bin field is empty; cannot execute")
	}

	var availableBins []string
	for name := range binMap {
		availableBins = append(availableBins, name)
	}
	sort.Strings(availableBins)

	if binName != "" {
		if _, ok := binMap[binName]; ok {
			binExecPath := filepath.Join(tempDir, "node_modules", ".bin", binName)
			if _, err := os.Stat(binExecPath); err == nil {
				return binExecPath, nil
			}
			return filepath.Join(pkgDir, binMap[binName]), nil
		}
		return "", fmt.Errorf("specified --bin %q not found; available: %s",
			binName, strings.Join(availableBins, ", "))
	}

	if _, ok := binMap[unscopedName]; ok {
		binExecPath := filepath.Join(tempDir, "node_modules", ".bin", unscopedName)
		if _, err := os.Stat(binExecPath); err == nil {
			return binExecPath, nil
		}
	}

	if len(binMap) == 1 {
		for name := range binMap {
			binExecPath := filepath.Join(tempDir, "node_modules", ".bin", name)
			if _, err := os.Stat(binExecPath); err == nil {
				return binExecPath, nil
			}
			return filepath.Join(pkgDir, binMap[name]), nil
		}
	}

	return "", fmt.Errorf("package exports multiple binaries (%s); use --bin <name> to choose one",
		strings.Join(availableBins, ", "))
}
