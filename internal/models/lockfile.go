package models

// ToolLock locked state
type ToolLock struct {
	DescriptionHash string    `json:"description_hash"`
	InputSchemaHash string    `json:"input_schema_hash"`
	RiskLevel       RiskLevel `json:"risk_level"`
}

// Lockfile is the json structure
type Lockfile struct {
	Version       string              `json:"version"`
	ServerCommand string              `json:"server_command"`
	Tools         map[string]ToolLock `json:"tools"`
}

// LockfileVersion current
const LockfileVersion = "1.0"
