// Package receipt provides stable evidence artifacts for audit/compliance.
package receipt

// ReceiptSchemaVersion current
const ReceiptSchemaVersion = "1.0"

// Receipt structure
type Receipt struct {
	SchemaVersion string           `json:"schema_version"`
	OpID          string           `json:"op_id"`
	TsStart       string           `json:"ts_start"`
	TsEnd         string           `json:"ts_end"`
	Command       string           `json:"command"`
	Args          []string         `json:"args"`
	ArgsRedacted  bool             `json:"args_redacted,omitempty"` // SEC-06: true if any args were sanitized
	Result        Result           `json:"result"`
	Lockfile      *LockfileRef     `json:"lockfile,omitempty"`
	Artifact      *ArtifactSummary `json:"artifact,omitempty"`
	Drift         *DriftSummary    `json:"drift,omitempty"`
	Policy        *PolicySummary   `json:"policy,omitempty"`
}

// Result status
type Result struct {
	Status string `json:"status"` // "success" or "fail"
	Error  string `json:"error,omitempty"`
}

// LockfileRef detail
type LockfileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

// ArtifactSummary detail
type ArtifactSummary struct {
	Type          string             `json:"type"` // npm|oci|git|binary|unknown
	Name          string             `json:"name,omitempty"`
	Version       string             `json:"version,omitempty"`
	Registry      string             `json:"registry,omitempty"`
	Integrity     string             `json:"integrity,omitempty"`
	TarballSHA256 string             `json:"tarball_sha256,omitempty"`
	Provenance    *ProvenanceSummary `json:"provenance,omitempty"`
}

// ProvenanceSummary detail
type ProvenanceSummary struct {
	Method     string `json:"method"` // cosign_slsa|npm_audit_signatures|unverified
	Verified   bool   `json:"verified"`
	SourceRepo string `json:"source_repo,omitempty"`
	BuilderID  string `json:"builder_id,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
}

// DriftSummary detail
type DriftSummary struct {
	Critical int    `json:"critical"`
	Benign   int    `json:"benign"`
	Summary  string `json:"summary,omitempty"`
}

// PolicySummary detail
type PolicySummary struct {
	Preset   string    `json:"preset,omitempty"` // baseline|strict|custom
	Status   string    `json:"status"`           // pass|warn|fail
	RulesHit []RuleHit `json:"rules_hit,omitempty"`
}

// RuleHit detail
type RuleHit struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"` // warn|error
	ControlRefs []string `json:"control_refs,omitempty"`
}
