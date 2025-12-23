package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type npmPackageLockFull struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmPackageInfo `json:"packages"`
	Dependencies    map[string]npmDepInfo     `json:"dependencies"`
}

type npmDepInfo struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

func InstalledResolvedFromPackageLock(lockPath, pkgName, version string) (string, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return "", fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	var lockfile npmPackageLockFull
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return "", fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	if lockfile.LockfileVersion >= 2 && lockfile.Packages != nil {
		keys := []string{
			"node_modules/" + pkgName,
			pkgName,
			"",
		}

		for _, key := range keys {
			if key == "" {
				continue
			}
			if pkg, ok := lockfile.Packages[key]; ok {
				if version != "" && pkg.Version != "" && pkg.Version != version {
					continue
				}
				return pkg.Resolved, nil
			}
		}
	}

	if lockfile.Dependencies != nil {
		if dep, ok := lockfile.Dependencies[pkgName]; ok {
			if version == "" || dep.Version == version {
				return dep.Resolved, nil
			}
		}
	}

	return "", nil
}

func ValidateLocalTarballResolved(resolved, expectedTarball string) error {
	if resolved == "" {
		return nil
	}

	resolvedLower := strings.ToLower(resolved)

	if strings.HasPrefix(resolvedLower, "file:") {
		return nil
	}

	if filepath.IsAbs(resolved) {
		if runtime.GOOS == "windows" && strings.HasPrefix(resolved, "\\\\") {
			return fmt.Errorf("network paths not supported for resolved: %q", resolved)
		}
		return nil
	}

	if strings.HasSuffix(resolvedLower, ".tgz") && !strings.HasPrefix(resolvedLower, "http") {
		return nil
	}

	if strings.HasPrefix(resolvedLower, "http://") || strings.HasPrefix(resolvedLower, "https://") {
		return fmt.Errorf("installed package resolved from registry %q, not local tarball\n"+
			"  This indicates npm fetched from registry instead of the verified local file.\n"+
			"  Expected: file:... or local path", resolved)
	}

	return nil
}

func ValidateInstalledPackageIdentity(nodeModulesPath, pkgName, expectedVersion string) error {
	pkgJSONPath := filepath.Join(nodeModulesPath, pkgName, "package.json")

	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return fmt.Errorf("failed to read installed package.json: %w", err)
	}

	var pkgJSON struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	if err := json.Unmarshal(data, &pkgJSON); err != nil {
		return fmt.Errorf("failed to parse installed package.json: %w", err)
	}

	if pkgJSON.Name != pkgName {
		return fmt.Errorf("installed package name %q does not match expected %q", pkgJSON.Name, pkgName)
	}

	if expectedVersion != "" && pkgJSON.Version != expectedVersion {
		return fmt.Errorf("installed package version %q does not match expected %q", pkgJSON.Version, expectedVersion)
	}

	return nil
}
