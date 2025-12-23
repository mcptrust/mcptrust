package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/models"
)

const (
	// DefaultNPMRegistry URL
	DefaultNPMRegistry = "https://registry.npmjs.org"

	// npmHTTPTimeout default
	npmHTTPTimeout = 30 * time.Second
)

// NPMClient registry accessor
type NPMClient struct {
	Registry   string
	HTTPClient *http.Client
}

// NewNPMClient constructor
func NewNPMClient(registry string) *NPMClient {
	if registry == "" {
		registry = DefaultNPMRegistry
	}
	return &NPMClient{
		Registry: strings.TrimSuffix(registry, "/"),
		HTTPClient: &http.Client{
			Timeout: npmHTTPTimeout,
		},
	}
}

// NPMDistInfo details
type NPMDistInfo struct {
	Tarball   string `json:"tarball"`   // Download URL
	Integrity string `json:"integrity"` // Subresource Integrity hash (sha512-...)
	Shasum    string `json:"shasum"`    // Legacy SHA-1 hash
}

// NPMPackageVersion details
type NPMPackageVersion struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Dist    NPMDistInfo `json:"dist"`
}

// NPMPackageMetadata details
type NPMPackageMetadata struct {
	Name        string                       `json:"name"`
	DistTags    map[string]string            `json:"dist-tags"` // e.g., {"latest": "1.2.3"}
	Versions    map[string]NPMPackageVersion `json:"versions"`
	Time        map[string]string            `json:"time"` // Version publish times
	Description string                       `json:"description"`
}

// FetchPackageMetadata
func (c *NPMClient) FetchPackageMetadata(ctx context.Context, packageName string) (*NPMPackageMetadata, error) {
	// Build URL: GET /{package}
	// For scoped packages, encode the scope: @scope/pkg -> @scope%2fpkg
	encodedName := url.PathEscape(packageName)
	// PathEscape encodes / as %2F, but npm registry expects @scope%2fpkg format
	// Actually npm accepts both /@scope/pkg and /@scope%2Fpkg
	url := fmt.Sprintf("%s/%s", c.Registry, encodedName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm registry request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found in registry", packageName)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("npm registry returned status %d: %s", resp.StatusCode, string(body))
	}

	var metadata NPMPackageMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse npm metadata: %w", err)
	}

	return &metadata, nil
}

// FetchVersionMetadata
func (c *NPMClient) FetchVersionMetadata(ctx context.Context, packageName, version string) (*NPMPackageVersion, error) {
	// Build URL: GET /{package}/{version}
	encodedName := url.PathEscape(packageName)
	url := fmt.Sprintf("%s/%s/%s", c.Registry, encodedName, version)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm registry request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("version %q of package %q not found", version, packageName)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("npm registry returned status %d: %s", resp.StatusCode, string(body))
	}

	var versionData NPMPackageVersion
	if err := json.NewDecoder(resp.Body).Decode(&versionData); err != nil {
		return nil, fmt.Errorf("failed to parse npm version metadata: %w", err)
	}

	return &versionData, nil
}

// ResolveVersion tags
func (c *NPMClient) ResolveVersion(ctx context.Context, packageName, versionSpec string) (string, error) {
	// Only support "latest" and exact versions for now
	// Semver ranges need a library

	if versionSpec == "" || versionSpec == "latest" {
		// Fetch package metadata to get dist-tags
		metadata, err := c.FetchPackageMetadata(ctx, packageName)
		if err != nil {
			return "", err
		}

		latest, ok := metadata.DistTags["latest"]
		if !ok {
			return "", fmt.Errorf("package %q has no 'latest' tag", packageName)
		}
		return latest, nil
	}

	// Check if it's a dist-tag (e.g., "next", "beta")
	if !strings.ContainsAny(versionSpec, "^~>=<") {
		// Could be exact version or dist-tag, try fetching directly
		metadata, err := c.FetchPackageMetadata(ctx, packageName)
		if err != nil {
			return "", err
		}

		// Check if it's a dist-tag
		if version, ok := metadata.DistTags[versionSpec]; ok {
			return version, nil
		}

		// Check if it's an exact version
		if _, ok := metadata.Versions[versionSpec]; ok {
			return versionSpec, nil
		}

		return "", fmt.Errorf("version %q not found for package %q", versionSpec, packageName)
	}

	// For semver ranges, we'd need a semver library
	// For now, return an error suggesting exact version
	return "", fmt.Errorf("semver ranges not supported yet, please specify exact version (e.g., 1.2.3)")
}

// CreateNPMPin from ref
func (c *NPMClient) CreateNPMPin(ctx context.Context, ref *NPMPackageRef) (*models.ArtifactPin, error) {
	// Resolve version if not exact
	version := ref.Version
	if version == "" {
		var err error
		version, err = c.ResolveVersion(ctx, ref.Name, "latest")
		if err != nil {
			return nil, fmt.Errorf("failed to resolve latest version: %w", err)
		}
	}

	// Fetch version metadata to get integrity hash and tarball URL
	versionData, err := c.FetchVersionMetadata(ctx, ref.Name, version)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch version metadata: %w", err)
	}

	pin := &models.ArtifactPin{
		Type:       models.ArtifactTypeNPM,
		Name:       ref.Name,
		Version:    versionData.Version,
		Registry:   c.Registry,
		Integrity:  versionData.Dist.Integrity,
		TarballURL: versionData.Dist.Tarball, // Always populate tarball URL
	}

	// Fall back to shasum if integrity not present (older packages)
	if pin.Integrity == "" && versionData.Dist.Shasum != "" {
		pin.Integrity = "sha1-" + versionData.Dist.Shasum
	}

	return pin, nil
}

// VerifyNPMIntegrity check
func (c *NPMClient) VerifyNPMIntegrity(ctx context.Context, pin *models.ArtifactPin) error {
	if pin.Type != models.ArtifactTypeNPM {
		return fmt.Errorf("pin is not an npm artifact")
	}

	versionData, err := c.FetchVersionMetadata(ctx, pin.Name, pin.Version)
	if err != nil {
		return fmt.Errorf("failed to fetch current registry metadata: %w", err)
	}

	currentIntegrity := versionData.Dist.Integrity
	if currentIntegrity == "" && versionData.Dist.Shasum != "" {
		currentIntegrity = "sha1-" + versionData.Dist.Shasum
	}

	if currentIntegrity != pin.Integrity {
		return fmt.Errorf("integrity mismatch: pinned %q, registry has %q", pin.Integrity, currentIntegrity)
	}

	return nil
}
