package artifact

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/netutil"
)

type ProvenanceVerifier struct {
	ExpectedSource string
}

type NPMProvenanceResult struct {
	Verified       bool
	VerifiedAt     time.Time
	Strategy       string // "cosign" or "npm"
	ToolVersion    string // Version string of the verification tool
	ProvenanceInfo *models.ProvenanceInfo
	RawStatement   json.RawMessage
	Error          error
}

type DSSEEnvelope struct {
	PayloadType string    `json:"payloadType"`
	Payload     string    `json:"payload"` // base64 encoded
	Signatures  []DSSESig `json:"signatures"`
}

type DSSESig struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type InTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type SLSAProvenanceV1 struct {
	BuildDefinition *BuildDefinition `json:"buildDefinition,omitempty"`
	RunDetails      *RunDetails      `json:"runDetails,omitempty"`
}

type BuildDefinition struct {
	BuildType          string                 `json:"buildType,omitempty"`
	ExternalParameters map[string]interface{} `json:"externalParameters,omitempty"`
	InternalParameters map[string]interface{} `json:"internalParameters,omitempty"`
}

type RunDetails struct {
	Builder  *Builder  `json:"builder,omitempty"`
	Metadata *Metadata `json:"metadata,omitempty"`
}

type Builder struct {
	ID                  string            `json:"id,omitempty"`
	Version             map[string]string `json:"version,omitempty"`
	BuilderDependencies []interface{}     `json:"builderDependencies,omitempty"`
}

type Metadata struct {
	InvocationID string `json:"invocationId,omitempty"`
}

type SLSAProvenanceOlder struct {
	Builder    *OlderBuilder    `json:"builder,omitempty"`
	Invocation *OlderInvocation `json:"invocation,omitempty"`
	Materials  []Material       `json:"materials,omitempty"`
}

type OlderBuilder struct {
	ID string `json:"id,omitempty"`
}

type OlderInvocation struct {
	ConfigSource *ConfigSource `json:"configSource,omitempty"`
}

type ConfigSource struct {
	URI        string            `json:"uri,omitempty"`
	Digest     map[string]string `json:"digest,omitempty"`
	EntryPoint string            `json:"entryPoint,omitempty"`
}

type Material struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type NPMAttestationsResponse struct {
	Attestations []NPMAttestation `json:"attestations"`
}

type NPMAttestation struct {
	PredicateType string          `json:"predicateType"`
	BundleURL     string          `json:"bundleUrl,omitempty"`
	Bundle        json.RawMessage `json:"bundle,omitempty"`
}

func VerifyNPMProvenance(ctx context.Context, pin *models.ArtifactPin, expectedSource string) (*NPMProvenanceResult, error) {
	if pin.Type != models.ArtifactTypeNPM {
		return nil, fmt.Errorf("artifact is not an npm package")
	}

	result, err := verifyNPMProvenanceWithCosign(ctx, pin, expectedSource)
	if err == nil && result.Verified {
		return result, nil
	}

	cosignErr := err

	result, err = verifyNPMProvenanceWithNPM(ctx, pin)
	if err == nil && result.Verified {
		return result, nil
	}

	// Both strategies failed
	if cosignErr != nil && err != nil {
		return nil, fmt.Errorf("provenance verification failed:\n  cosign: %v\n  npm: %v\n\nNote: Provenance verification requires cosign >= 2.4.1 or npm >= 9.5.0", cosignErr, err)
	}
	if cosignErr != nil {
		return nil, fmt.Errorf("provenance verification failed: %v", cosignErr)
	}
	return nil, fmt.Errorf("provenance verification failed: %v", err)
}

func verifyNPMProvenanceWithCosign(ctx context.Context, pin *models.ArtifactPin, expectedSource string) (*NPMProvenanceResult, error) {
	versionStr, err := checkCosignVersion(ctx)
	if err != nil {
		return nil, err
	}

	client := NewNPMClient(pin.Registry)
	versionData, err := client.FetchVersionMetadata(ctx, pin.Name, pin.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch npm metadata: %w", err)
	}

	tarballPath, cleanup, err := downloadTarball(ctx, versionData.Dist.Tarball, false)
	if err != nil {
		return nil, fmt.Errorf("failed to download tarball: %w", err)
	}
	defer cleanup()

	bundleJSON, err := fetchNPMAttestationBundle(ctx, pin.Name, pin.Version, pin.Registry)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestation bundle: %w", err)
	}

	bundlePath, err := writeTempFile(bundleJSON, "npm-attestation-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to write bundle file: %w", err)
	}
	defer os.Remove(bundlePath)

	identityRegex := ".*"
	if expectedSource != "" {
		identityRegex = expectedSource + ".*"
	}

	// Run cosign verify-blob-attestation
	args := []string{
		"verify-blob-attestation",
		"--bundle", bundlePath,
		"--new-bundle-format",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		"--certificate-identity-regexp", identityRegex,
		tarballPath,
	}

	stdout, stderr, err := runCommand(ctx, "cosign", args, nil)
	if err != nil {
		return &NPMProvenanceResult{
			Verified: false,
			Strategy: "cosign",
			Error:    fmt.Errorf("cosign verification failed: %s %s", string(stdout), string(stderr)),
		}, nil
	}

	provenanceInfo, rawStatement, err := parseNPMAttestationBundle(bundleJSON, expectedSource)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", err)
	}

	provenanceInfo.Method = models.ProvenanceMethodCosignSLSA
	provenanceInfo.Verified = true
	provenanceInfo.VerifiedAt = time.Now().UTC().Format(time.RFC3339)

	return &NPMProvenanceResult{
		Verified:       true,
		VerifiedAt:     time.Now().UTC(),
		Strategy:       "cosign",
		ToolVersion:    versionStr,
		ProvenanceInfo: provenanceInfo,
		RawStatement:   rawStatement,
	}, nil
}

func verifyNPMProvenanceWithNPM(ctx context.Context, pin *models.ArtifactPin) (*NPMProvenanceResult, error) {
	if !isNPMAvailable(ctx) {
		return nil, fmt.Errorf("npm not found in PATH")
	}

	tempDir, err := os.MkdirTemp("", "mcptrust-npm-verify-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	initCmd := exec.CommandContext(ctx, "npm", "init", "-y")
	initCmd.Dir = tempDir
	if err := initCmd.Run(); err != nil {
		return nil, fmt.Errorf("npm init failed: %w", err)
	}

	packageSpec := fmt.Sprintf("%s@%s", pin.Name, pin.Version)
	installCmd := exec.CommandContext(ctx, "npm", "install", packageSpec, "--ignore-scripts")
	installCmd.Dir = tempDir
	if output, err := installCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("npm install failed: %s - %w", string(output), err)
	}

	auditCmd := exec.CommandContext(ctx, "npm", "audit", "signatures")
	auditCmd.Dir = tempDir
	output, err := auditCmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		return &NPMProvenanceResult{
			Verified: false,
			Strategy: "npm",
			Error:    fmt.Errorf("npm audit signatures failed: %s", outputStr),
		}, nil
	}

	provenanceInfo := &models.ProvenanceInfo{
		Method:     models.ProvenanceMethodNPMAuditSigs,
		Verified:   true,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}

	_ = strings.Contains(outputStr, "verified")

	return &NPMProvenanceResult{
		Verified:       true,
		VerifiedAt:     time.Now().UTC(),
		Strategy:       "npm",
		ProvenanceInfo: provenanceInfo,
	}, nil
}

func fetchNPMAttestationBundle(ctx context.Context, name, version, registry string) ([]byte, error) {
	if registry == "" {
		registry = DefaultNPMRegistry
	}

	encodedSpec := strings.ReplaceAll(fmt.Sprintf("%s@%s", name, version), "/", "%2F")
	url := fmt.Sprintf("%s/-/npm/v1/attestations/%s", registry, encodedSpec)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attestation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no attestations found for %s@%s (package may not have provenance)", name, version)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("attestation API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var attestResp NPMAttestationsResponse
	if err := json.Unmarshal(body, &attestResp); err != nil {
		return nil, fmt.Errorf("failed to parse attestations response: %w", err)
	}

	for _, att := range attestResp.Attestations {
		if strings.HasPrefix(att.PredicateType, "https://slsa.dev/provenance") {
			if len(att.Bundle) > 0 {
				return att.Bundle, nil
			}
			if att.BundleURL != "" {
				return fetchURL(ctx, att.BundleURL)
			}
		}
	}

	return nil, fmt.Errorf("no SLSA provenance attestation found in response")
}

func parseNPMAttestationBundle(bundleJSON []byte, expectedSource string) (*models.ProvenanceInfo, json.RawMessage, error) {
	// Parse as DSSE envelope or Sigstore bundle
	var envelope DSSEEnvelope
	if err := json.Unmarshal(bundleJSON, &envelope); err == nil && envelope.Payload != "" {
		payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
		}
		return parseInTotoStatement(payloadBytes, expectedSource)
	}

	var bundle map[string]interface{}
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return nil, nil, fmt.Errorf("failed to parse attestation bundle: %w", err)
	}

	if dsseEnvelope, ok := bundle["dsseEnvelope"].(map[string]interface{}); ok {
		if payload, ok := dsseEnvelope["payload"].(string); ok {
			payloadBytes, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
			}
			return parseInTotoStatement(payloadBytes, expectedSource)
		}
	}

	return nil, nil, fmt.Errorf("unable to extract attestation statement from bundle")
}

func parseInTotoStatement(statementBytes []byte, expectedSource string) (*models.ProvenanceInfo, json.RawMessage, error) {
	var statement InTotoStatement
	if err := json.Unmarshal(statementBytes, &statement); err != nil {
		return nil, nil, fmt.Errorf("failed to parse in-toto statement: %w", err)
	}

	if !strings.HasPrefix(statement.PredicateType, "https://slsa.dev/provenance") {
		return nil, nil, fmt.Errorf("not a SLSA provenance attestation: predicateType=%s", statement.PredicateType)
	}

	info := &models.ProvenanceInfo{}

	info.PredicateType = statement.PredicateType

	var v1Predicate SLSAProvenanceV1
	if err := json.Unmarshal(statement.Predicate, &v1Predicate); err == nil && v1Predicate.RunDetails != nil {
		if v1Predicate.RunDetails.Builder != nil {
			info.BuilderID = v1Predicate.RunDetails.Builder.ID
		}
		if v1Predicate.BuildDefinition != nil && v1Predicate.BuildDefinition.ExternalParameters != nil {
			if repo, ok := v1Predicate.BuildDefinition.ExternalParameters["repository"].(string); ok {
				info.SourceRepo = repo
			}
			if ref, ok := v1Predicate.BuildDefinition.ExternalParameters["ref"].(string); ok {
				info.SourceRef = ref
			}
			if workflow, ok := v1Predicate.BuildDefinition.ExternalParameters["workflow"].(map[string]interface{}); ok {
				if path, ok := workflow["path"].(string); ok {
					info.WorkflowURI = path
				}
			}
		}
	} else {
		var olderPredicate SLSAProvenanceOlder
		if err := json.Unmarshal(statement.Predicate, &olderPredicate); err == nil {
			if olderPredicate.Builder != nil {
				info.BuilderID = olderPredicate.Builder.ID
			}
			if olderPredicate.Invocation != nil && olderPredicate.Invocation.ConfigSource != nil {
				info.SourceRepo = olderPredicate.Invocation.ConfigSource.URI
				info.WorkflowURI = olderPredicate.Invocation.ConfigSource.EntryPoint
				if sha, ok := olderPredicate.Invocation.ConfigSource.Digest["sha1"]; ok {
					info.SourceRef = sha
				}
			}
			for _, mat := range olderPredicate.Materials {
				if strings.Contains(mat.URI, "github.com") && info.SourceRepo == "" {
					info.SourceRepo = mat.URI
					if sha, ok := mat.Digest["sha1"]; ok {
						info.SourceRef = sha
					}
				}
			}
		}
	}

	if expectedSource != "" && info.SourceRepo != "" {
		matched, err := regexp.MatchString(expectedSource, info.SourceRepo)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid expected source regex: %w", err)
		}
		if !matched {
			return nil, nil, fmt.Errorf("source repository %q does not match expected pattern %q", info.SourceRepo, expectedSource)
		}
	}

	return info, statementBytes, nil
}

func isCosignAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "cosign", "version")
	return cmd.Run() == nil
}

func isNPMAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "npm", "--version")
	return cmd.Run() == nil
}

func downloadTarball(ctx context.Context, tarballURL string, allowPrivateHosts bool) (string, func(), error) {
	config := netutil.DefaultConfig()
	config.AllowPrivateHosts = allowPrivateHosts

	result, err := netutil.DownloadTarball(ctx, tarballURL, config)
	if err != nil {
		return "", nil, err
	}

	return result.Path, result.Cleanup, nil
}

func writeTempFile(data []byte, pattern string) (string, error) {
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(data); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

func fetchURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func runCommand(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func GetWorkflowPath(identity string) string {
	parts := strings.Split(identity, "/.github/workflows/")
	if len(parts) != 2 {
		return ""
	}
	workflow := parts[1]
	if atIdx := strings.Index(workflow, "@"); atIdx != -1 {
		workflow = workflow[:atIdx]
	}
	return filepath.Join(".github/workflows", workflow)
}

func checkCosignVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "cosign", "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cosign not found in PATH")
	}

	versionStr := string(output)

	re := regexp.MustCompile(`(?:v|version\s*)?(\d+)\.(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(versionStr)

	if len(matches) < 4 {
		return "", fmt.Errorf("unable to parse cosign version from output: %q", strings.TrimSpace(versionStr))
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])

	isValid := false
	if major > 2 {
		isValid = true
	} else if major == 2 {
		if minor > 4 {
			isValid = true
		} else if minor == 4 {
			if patch >= 1 {
				isValid = true
			}
		}
	}

	if !isValid {
		return "", fmt.Errorf("found cosign v%d.%d.%d, need >= 2.4.1 for provenance verification", major, minor, patch)
	}

	return strings.TrimSpace(versionStr), nil
}

type TarballDownloadResult struct {
	Path    string
	Size    int64
	Cleanup func()
}

func DownloadTarballForVerification(ctx context.Context, pin *models.ArtifactPin, allowPrivateHosts bool) (*TarballDownloadResult, error) {
	if pin.Type != models.ArtifactTypeNPM {
		return nil, fmt.Errorf("DownloadTarballForVerification only supports npm artifacts")
	}

	tarballURL := pin.TarballURL
	if tarballURL == "" {
		client := NewNPMClient(pin.Registry)
		versionData, err := client.FetchVersionMetadata(ctx, pin.Name, pin.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch npm metadata: %w", err)
		}
		tarballURL = versionData.Dist.Tarball
	}

	path, cleanup, err := downloadTarball(ctx, tarballURL, allowPrivateHosts)
	if err != nil {
		return nil, fmt.Errorf("failed to download tarball: %w", err)
	}

	var size int64
	if info, err := os.Stat(path); err == nil {
		size = info.Size()
	}

	return &TarballDownloadResult{
		Path:    path,
		Size:    size,
		Cleanup: cleanup,
	}, nil
}
