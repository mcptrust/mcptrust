package models

// PolicyMode enum
type PolicyMode string

const (
	PolicyModeWarn   PolicyMode = "warn"   // Warnings don't fail the check
	PolicyModeStrict PolicyMode = "strict" // Any failure is fatal
)

// PolicySeverity enum
type PolicySeverity string

const (
	PolicySeverityWarn  PolicySeverity = "warn"
	PolicySeverityError PolicySeverity = "error"
)

// PolicyConfig schema
type PolicyConfig struct {
	Name  string       `yaml:"name"`
	Mode  PolicyMode   `yaml:"mode,omitempty"` // "warn" | "strict" (default: strict)
	Rules []PolicyRule `yaml:"rules"`
}

// PolicyRule definition
type PolicyRule struct {
	Name       string         `yaml:"name" json:"name"`
	Expr       string         `yaml:"expr" json:"expr"`
	FailureMsg string         `yaml:"failure_msg" json:"failure_msg"`
	Severity   PolicySeverity `yaml:"severity,omitempty" json:"severity,omitempty"` // "warn" | "error" (default: error)
	// Optional metadata for explainability (does not affect enforcement)
	ControlRefs      []string `yaml:"control_refs,omitempty" json:"control_refs,omitempty"`
	Evidence         []string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	EvidenceCommands []string `yaml:"evidence_commands,omitempty" json:"evidence_commands,omitempty"`
}

// PolicyResult outcome
type PolicyResult struct {
	RuleName   string
	Passed     bool
	FailureMsg string
	Severity   PolicySeverity // Inherited from rule
}
