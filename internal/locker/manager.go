package locker

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dtang19/mcptrust/internal/models"
)

// DriftType indicates what kind of drift was detected
type DriftType string

const (
	DriftTypeDescriptionChanged DriftType = "description_changed"
	DriftTypeSchemaChanged      DriftType = "schema_changed"
	DriftTypeRiskLevelChanged   DriftType = "risk_level_changed"
	DriftTypeToolAdded          DriftType = "tool_added"
	DriftTypeToolRemoved        DriftType = "tool_removed"
)

// DriftItem detected change
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

// Save to disk
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

// Load from disk
func (m *Manager) Load(path string) (*models.Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read lockfile: %w", err)
	}

	var lockfile models.Lockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse lockfile: %w", err)
	}

	return &lockfile, nil
}

func (m *Manager) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DetectDrift returns changes
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
		return fmt.Sprintf("Tool [%s] has been ADDED!", d.ToolName)
	case DriftTypeToolRemoved:
		return fmt.Sprintf("Tool [%s] has been REMOVED!", d.ToolName)
	case DriftTypeDescriptionChanged:
		return fmt.Sprintf("Tool [%s] has changed capabilities! (description modified)", d.ToolName)
	case DriftTypeSchemaChanged:
		return fmt.Sprintf("Tool [%s] has changed capabilities! (input schema modified)", d.ToolName)
	case DriftTypeRiskLevelChanged:
		return fmt.Sprintf("Tool [%s] risk level changed from %s to %s", d.ToolName, d.OldValue, d.NewValue)
	default:
		return fmt.Sprintf("Tool [%s] has unknown drift type", d.ToolName)
	}
}
