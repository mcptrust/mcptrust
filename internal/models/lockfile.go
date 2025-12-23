package models

// ArtifactType enum
type ArtifactType string

const (
	ArtifactTypeNPM   ArtifactType = "npm"
	ArtifactTypeOCI   ArtifactType = "oci"
	ArtifactTypeLocal ArtifactType = "local"
)

// ProvenanceMethod enum
type ProvenanceMethod string

const (
	// ProvenanceMethodCosignSLSA = true SLSA via cosign
	ProvenanceMethodCosignSLSA ProvenanceMethod = "cosign_slsa"
	// ProvenanceMethodNPMAuditSigs = npm signatures only (no SLSA metadata)
	ProvenanceMethodNPMAuditSigs ProvenanceMethod = "npm_audit_signatures"
	// ProvenanceMethodUnverified = not verified/unavailable
	ProvenanceMethodUnverified ProvenanceMethod = "unverified"
)

// ProvenanceInfo details
type ProvenanceInfo struct {
	// Method indicates how provenance was verified (cosign_slsa, npm_audit_signatures, none)
	Method ProvenanceMethod `json:"method,omitempty"`

	// Raw predicate type for transparency
	PredicateType string `json:"predicate_type,omitempty"` // e.g., "https://slsa.dev/provenance/v1"

	// Normalized fields (extracted from various SLSA predicate shapes)
	BuilderID   string `json:"builder_id,omitempty"`   // SLSA builder identity
	SourceRepo  string `json:"source_repo,omitempty"`  // e.g., "https://github.com/org/repo"
	SourceRef   string `json:"source_ref,omitempty"`   // e.g., "refs/tags/v1.2.3"
	WorkflowURI string `json:"workflow_uri,omitempty"` // e.g., ".github/workflows/release.yml"

	// Certificate identity (from Sigstore verification)
	Issuer   string `json:"issuer,omitempty"`   // OIDC issuer
	Identity string `json:"identity,omitempty"` // Certificate identity

	// Verification status
	Verified   bool   `json:"verified"`              // true if attestation validated
	VerifiedAt string `json:"verified_at,omitempty"` // RFC3339 timestamp
}

// ArtifactPin definition
type ArtifactPin struct {
	Type ArtifactType `json:"type"` // "npm" | "oci" | "local"

	// npm fields
	Name      string `json:"name,omitempty"`      // e.g., "@modelcontextprotocol/server-filesystem"
	Version   string `json:"version,omitempty"`   // exact version: "1.2.3"
	Registry  string `json:"registry,omitempty"`  // "https://registry.npmjs.org"
	Integrity string `json:"integrity,omitempty"` // "sha512-abc123..." (npm dist.integrity, canonical)

	// Tarball pinning (npm) - additive fields for auditability
	TarballURL    string `json:"tarball_url,omitempty"`    // exact dist.tarball URL from registry
	TarballSHA256 string `json:"tarball_sha256,omitempty"` // hex SHA-256 of tarball bytes
	TarballSize   int64  `json:"tarball_size,omitempty"`   // tarball size in bytes (debugging/caching)

	// OCI fields
	Image  string `json:"image,omitempty"`  // "ghcr.io/org/server"
	Digest string `json:"digest,omitempty"` // "sha256:abc123..."

	// Provenance (optional, populated if verified)
	Provenance *ProvenanceInfo `json:"provenance,omitempty"`
}

// ToolLock definition
type ToolLock struct {
	DescriptionHash string    `json:"description_hash"`
	InputSchemaHash string    `json:"input_schema_hash"`
	RiskLevel       RiskLevel `json:"risk_level"`
}

// Lockfile schema
type Lockfile struct {
	Version       string              `json:"version"`
	ServerCommand string              `json:"server_command"`
	Artifact      *ArtifactPin        `json:"artifact,omitempty"` // Pinned artifact coordinates
	Tools         map[string]ToolLock `json:"tools"`
}

// LockfileVersion current
const LockfileVersion = "2.0"

// LockfileVersionLegacy for backward compatibility
const LockfileVersionLegacy = "1.0"
