package runner

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ComputeTarballSRI helper
func ComputeTarballSRI(tarballPath string) (string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return "", fmt.Errorf("failed to open tarball: %w", err)
	}
	defer f.Close()

	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to hash tarball: %w", err)
	}

	return fmt.Sprintf("sha512-%s", base64.StdEncoding.EncodeToString(h.Sum(nil))), nil
}

// NormalizeSRI helper
func NormalizeSRI(sri string) string {
	sri = strings.TrimSpace(sri)
	if sri == "" {
		return ""
	}

	// SRI format: algorithm-base64hash
	parts := strings.SplitN(sri, "-", 2)
	if len(parts) != 2 {
		return sri
	}

	// Lowercase the algorithm, preserve the hash exactly (base64 is case-sensitive)
	return strings.ToLower(parts[0]) + "-" + parts[1]
}

// ValidateSRIFormat
func ValidateSRIFormat(sri string) error {
	sri = strings.TrimSpace(sri)
	if sri == "" {
		return nil
	}

	// Check for multi-hash SRI (space-separated algorithms)
	if strings.Contains(sri, " ") {
		return fmt.Errorf("multi-hash SRI detected (multiple space-separated hashes)\n"+
			"  Received: %q\n"+
			"  mcptrust only supports single-algorithm SRI (e.g., sha512-...)\n"+
			"  To fix: re-run 'mcptrust lock --pin' which uses single sha512 hash\n"+
			"  Or file an issue if multi-hash support is needed", sri)
	}

	// Check basic format
	parts := strings.SplitN(sri, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid SRI format\n"+
			"  Received: %q\n"+
			"  Expected: algorithm-base64hash (e.g., sha512-abc123...)", sri)
	}

	return nil
}

// npmPackageLockV2 schema
type npmPackageLockV2 struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmPackageInfo `json:"packages"`
}

// npmPackageInfo schema
type npmPackageInfo struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

// InstalledIntegrityFromPackageLock
func InstalledIntegrityFromPackageLock(lockPath, pkgName, version string) (string, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return "", fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	var lockfile npmPackageLockV2
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return "", fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	// Lockfile v2/v3 uses "packages" with keys like "node_modules/@scope/name"
	if lockfile.LockfileVersion >= 2 && lockfile.Packages != nil {
		// Try different key formats npm might use
		keys := []string{
			"node_modules/" + pkgName,
			pkgName,
		}

		for _, key := range keys {
			if pkg, ok := lockfile.Packages[key]; ok {
				// Verify version matches if specified
				if version != "" && pkg.Version != version {
					continue
				}
				if pkg.Integrity != "" {
					return pkg.Integrity, nil
				}
			}
		}
	}

	return "", fmt.Errorf("package %s@%s not found in package-lock.json", pkgName, version)
}

// VerifyIntegrityMatch
func VerifyIntegrityMatch(expected, actual, context string) error {
	expectedNorm := NormalizeSRI(expected)
	actualNorm := NormalizeSRI(actual)

	if expectedNorm != actualNorm {
		return fmt.Errorf("integrity mismatch (%s):\n  expected: %s\n  actual:   %s",
			context, expected, actual)
	}
	return nil
}
