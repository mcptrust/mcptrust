package locker

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mcptrust/mcptrust/internal/models"
)

// DriftType enum
type DriftType string

const (
	DriftTypeDescriptionChanged DriftType = "description_changed"
	DriftTypeSchemaChanged      DriftType = "schema_changed"
	DriftTypeRiskLevelChanged   DriftType = "risk_level_changed"
	DriftTypeToolAdded          DriftType = "tool_added"
	DriftTypeToolRemoved        DriftType = "tool_removed"
)

// DriftItem details
type DriftItem struct {
	ToolName  string
	DriftType DriftType
	OldValue  string
	NewValue  string
}

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

// CreateLockfile from scan
func (m *Manager) CreateLockfile(report *models.ScanReport) (*models.Lockfile, error) {
	lockfile := &models.Lockfile{
		Version:       models.LockfileVersion,
		ServerCommand: report.Command,
		Tools:         make(map[string]models.ToolLock),
	}

	for _, tool := range report.Tools {
		descHash := HashString(tool.Description)

		schemaHash, err := HashJSON(tool.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("failed to hash schema for tool %s: %w", tool.Name, err)
		}

		lockfile.Tools[tool.Name] = models.ToolLock{
			DescriptionHash: descHash,
			InputSchemaHash: schemaHash,
			RiskLevel:       tool.RiskLevel,
		}
	}

	return lockfile, nil
}

// Save lockfile
func (m *Manager) Save(lockfile *models.Lockfile, path string) error {
	data, err := json.MarshalIndent(lockfile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal lockfile: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write lockfile: %w", err)
	}

	return nil
}

// Load lockfile
func (m *Manager) Load(path string) (*models.Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read lockfile: %w", err)
	}

	var lockfile models.Lockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse lockfile: %w", err)
	}

	// Backward compatibility: If provenance exists but Method is empty,
	// default to "unverified" for stable behavior with older lockfiles
	if lockfile.Artifact != nil && lockfile.Artifact.Provenance != nil {
		if lockfile.Artifact.Provenance.Method == "" {
			lockfile.Artifact.Provenance.Method = models.ProvenanceMethodUnverified
		}
	}

	return &lockfile, nil
}

func (m *Manager) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DetectDrift changes
func (m *Manager) DetectDrift(existing, new *models.Lockfile) []DriftItem {
	var drifts []DriftItem

	// removed
	for name := range existing.Tools {
		if _, found := new.Tools[name]; !found {
			drifts = append(drifts, DriftItem{
				ToolName:  name,
				DriftType: DriftTypeToolRemoved,
			})
		}
	}

	// added/changed
	for name, newTool := range new.Tools {
		existingTool, found := existing.Tools[name]
		if !found {
			drifts = append(drifts, DriftItem{
				ToolName:  name,
				DriftType: DriftTypeToolAdded,
			})
			continue
		}

		// desc changes
		if existingTool.DescriptionHash != newTool.DescriptionHash {
			drifts = append(drifts, DriftItem{
				ToolName:  name,
				DriftType: DriftTypeDescriptionChanged,
				OldValue:  existingTool.DescriptionHash,
				NewValue:  newTool.DescriptionHash,
			})
		}

		// schema changes
		if existingTool.InputSchemaHash != newTool.InputSchemaHash {
			drifts = append(drifts, DriftItem{
				ToolName:  name,
				DriftType: DriftTypeSchemaChanged,
				OldValue:  existingTool.InputSchemaHash,
				NewValue:  newTool.InputSchemaHash,
			})
		}

		// risk changes
		if existingTool.RiskLevel != newTool.RiskLevel {
			drifts = append(drifts, DriftItem{
				ToolName:  name,
				DriftType: DriftTypeRiskLevelChanged,
				OldValue:  string(existingTool.RiskLevel),
				NewValue:  string(newTool.RiskLevel),
			})
		}
	}

	return drifts
}

// FormatDriftError human readable
func FormatDriftError(d DriftItem) string {
	switch d.DriftType {
	case DriftTypeToolAdded:
		return fmt.Sprintf("Tool [%s] ADDED", d.ToolName)
	case DriftTypeToolRemoved:
		return fmt.Sprintf("Tool [%s] REMOVED", d.ToolName)
	case DriftTypeDescriptionChanged:
		return fmt.Sprintf("Tool [%s] capabilities changed (description)", d.ToolName)
	case DriftTypeSchemaChanged:
		return fmt.Sprintf("Tool [%s] capabilities changed (schema)", d.ToolName)
	case DriftTypeRiskLevelChanged:
		return fmt.Sprintf("Tool [%s] risk: %s -> %s", d.ToolName, d.OldValue, d.NewValue)
	default:
		return fmt.Sprintf("Tool [%s] unknown drift", d.ToolName)
	}
}

// SaveV3 lockfile
func (m *Manager) SaveV3(lockfile *models.LockfileV3, path string) error {
	data, err := json.MarshalIndent(lockfile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal v3 lockfile: %w", err)
	}

	// Ensure file ends with newline for clean git diffs
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write v3 lockfile: %w", err)
	}

	return nil
}

// LoadV3 lockfile
func (m *Manager) LoadV3(path string) (*models.LockfileV3, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read v3 lockfile: %w", err)
	}

	var lockfile models.LockfileV3
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse v3 lockfile: %w", err)
	}

	// Backward compatibility: ensure artifact provenance method is set
	if lockfile.Server.Artifact != nil && lockfile.Server.Artifact.Provenance != nil {
		if lockfile.Server.Artifact.Provenance.Method == "" {
			lockfile.Server.Artifact.Provenance.Method = models.ProvenanceMethodUnverified
		}
	}

	return &lockfile, nil
}

// DetectLockfileVersion check
func (m *Manager) DetectLockfileVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read lockfile: %w", err)
	}

	var versionOnly struct {
		Version         string `json:"version"`
		LockFileVersion string `json:"lockFileVersion"`
	}
	if err := json.Unmarshal(data, &versionOnly); err != nil {
		return "", fmt.Errorf("failed to parse lockfile version: %w", err)
	}

	// v3 uses lockFileVersion field
	if versionOnly.LockFileVersion != "" {
		return versionOnly.LockFileVersion, nil
	}
	// v1/v2 use version field
	if versionOnly.Version != "" {
		return versionOnly.Version, nil
	}

	return "", fmt.Errorf("unable to determine lockfile version")
}
