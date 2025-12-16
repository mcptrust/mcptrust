package bundler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
)

// BundleManifest contents
type BundleManifest struct {
	ToolVersion   string         `json:"tool_version"`
	Files         []ManifestFile `json:"files"`
	LockfileHash  string         `json:"lockfile_hash"`
	SignatureHash string         `json:"signature_hash"`
	CanonVersion  string         `json:"canon_version,omitempty"`
}

// ManifestFile desc
type ManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// GenerateManifest for contents
func GenerateManifest(opts BundleOptions, canonVersion string) (*BundleManifest, error) {
	manifest := &BundleManifest{
		ToolVersion:  getToolVersion(),
		Files:        []ManifestFile{},
		CanonVersion: canonVersion,
	}

	// hash lockfile
	lockHash, lockSize, err := hashFile(opts.LockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash lockfile: %w", err)
	}
	manifest.LockfileHash = lockHash
	manifest.Files = append(manifest.Files, ManifestFile{
		Name:   "mcp-lock.json",
		SHA256: lockHash,
		Size:   lockSize,
	})

	// hash signature
	sigHash, sigSize, err := hashFile(opts.SignaturePath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash signature: %w", err)
	}
	manifest.SignatureHash = sigHash
	manifest.Files = append(manifest.Files, ManifestFile{
		Name:   "mcp-lock.json.sig",
		SHA256: sigHash,
		Size:   sigSize,
	})

	// optional: public key
	if opts.PublicKeyPath != "" {
		if hash, size, err := hashFile(opts.PublicKeyPath); err == nil {
			manifest.Files = append(manifest.Files, ManifestFile{
				Name:   "public.key",
				SHA256: hash,
				Size:   size,
			})
		}
	}

	// optional: policy
	if opts.PolicyPath != "" {
		if hash, size, err := hashFile(opts.PolicyPath); err == nil {
			manifest.Files = append(manifest.Files, ManifestFile{
				Name:   "policy.yaml",
				SHA256: hash,
				Size:   size,
			})
		}
	}

	// sort files
	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Name < manifest.Files[j].Name
	})

	return manifest, nil
}

// ToJSON deterministic
func (m *BundleManifest) ToJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

func hashFile(path string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), int64(len(data)), nil
}

func getToolVersion() string {
	info, ok := debug.ReadBuildInfo()
	if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
