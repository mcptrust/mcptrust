package differ

import (
	"fmt"

	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/models"
)

// V3DriftType enum
type V3DriftType string

const (
	V3DriftPromptAdded       V3DriftType = "PROMPT_ADDED"
	V3DriftPromptRemoved     V3DriftType = "PROMPT_REMOVED"
	V3DriftPromptArgsChanged V3DriftType = "PROMPT_ARGS_CHANGED"
	V3DriftPromptDescChanged V3DriftType = "PROMPT_DESC_CHANGED"
	V3DriftTemplateAdded     V3DriftType = "TEMPLATE_ADDED"
	V3DriftTemplateRemoved   V3DriftType = "TEMPLATE_REMOVED"
	V3DriftTemplateChanged   V3DriftType = "TEMPLATE_CHANGED"
	V3DriftToolAdded         V3DriftType = "TOOL_ADDED"
	V3DriftToolRemoved       V3DriftType = "TOOL_REMOVED"
	V3DriftToolChanged       V3DriftType = "TOOL_CHANGED"
)

// V3DriftItem details
type V3DriftItem struct {
	Type       V3DriftType
	Severity   SeverityLevel // uses existing SeverityLevel from translator.go
	Identifier string        // prompt name or uriTemplate
	OldHash    string        // for meaningful PR comments
	NewHash    string
	Message    string
}

// V3Result details
type V3Result struct {
	HasDrift bool
	Drifts   []V3DriftItem
}

// CompareV3 lockfile v3 vs scan
func CompareV3(lockfile *models.LockfileV3, report *models.ScanReport) (*V3Result, error) {
	result := &V3Result{
		HasDrift: false,
		Drifts:   []V3DriftItem{},
	}

	// Compare prompts
	promptDrifts, err := comparePrompts(lockfile, report)
	if err != nil {
		return nil, fmt.Errorf("failed to compare prompts: %w", err)
	}
	result.Drifts = append(result.Drifts, promptDrifts...)

	// Compare templates
	templateDrifts, err := compareTemplates(lockfile, report)
	if err != nil {
		return nil, fmt.Errorf("failed to compare templates: %w", err)
	}
	result.Drifts = append(result.Drifts, templateDrifts...)

	// Compare tools
	toolDrifts, err := compareTools(lockfile, report)
	if err != nil {
		return nil, fmt.Errorf("failed to compare tools: %w", err)
	}
	result.Drifts = append(result.Drifts, toolDrifts...)

	result.HasDrift = len(result.Drifts) > 0
	return result, nil
}

// comparePrompts helper
func comparePrompts(lockfile *models.LockfileV3, report *models.ScanReport) ([]V3DriftItem, error) {
	var drifts []V3DriftItem

	// Build map of current prompts from scan
	currentPrompts := make(map[string]models.Prompt)
	for _, p := range report.Prompts {
		currentPrompts[p.Name] = p
	}

	// Check for removed prompts (in lockfile but not in scan)
	for name := range lockfile.Prompts.Definitions {
		if _, found := currentPrompts[name]; !found {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftPromptRemoved,
				Severity:   SeverityCritical,
				Identifier: name,
				Message:    fmt.Sprintf("Prompt [%s] has been removed from the server", name),
			})
		}
	}

	// Check for added or changed prompts
	for _, prompt := range report.Prompts {
		lockedDef, found := lockfile.Prompts.Definitions[prompt.Name]
		if !found {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftPromptAdded,
				Severity:   SeverityCritical,
				Identifier: prompt.Name,
				Message:    fmt.Sprintf("Prompt [%s] has been added to the server", prompt.Name),
			})
			continue
		}

		// Check arguments hash
		currentArgsHash, err := locker.HashPromptArguments(prompt.Arguments)
		if err != nil {
			return nil, fmt.Errorf("failed to hash arguments for prompt %s: %w", prompt.Name, err)
		}

		if lockedDef.ArgumentsHash != currentArgsHash {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftPromptArgsChanged,
				Severity:   SeverityCritical,
				Identifier: prompt.Name,
				OldHash:    lockedDef.ArgumentsHash,
				NewHash:    currentArgsHash,
				Message:    fmt.Sprintf("Prompt [%s] arguments changed: %s → %s", prompt.Name, truncHash(lockedDef.ArgumentsHash), truncHash(currentArgsHash)),
			})
		}

		// Check description hash (only if locked had one)
		if lockedDef.DescriptionHash != "" {
			currentDescHash := locker.HashNormalizedString(prompt.Description)
			if lockedDef.DescriptionHash != currentDescHash {
				drifts = append(drifts, V3DriftItem{
					Type:       V3DriftPromptDescChanged,
					Severity:   SeverityModerate,
					Identifier: prompt.Name,
					OldHash:    lockedDef.DescriptionHash,
					NewHash:    currentDescHash,
					Message:    fmt.Sprintf("Prompt [%s] description changed", prompt.Name),
				})
			}
		}
	}

	return drifts, nil
}

// compareTemplates helper
func compareTemplates(lockfile *models.LockfileV3, report *models.ScanReport) ([]V3DriftItem, error) {
	var drifts []V3DriftItem

	// Build map of locked templates
	lockedTemplates := make(map[string]models.ResourceTemplateLock)
	for _, t := range lockfile.Resources.Templates {
		lockedTemplates[t.URITemplate] = t
	}

	// Build map of current templates from scan
	currentTemplates := make(map[string]models.ResourceTemplate)
	for _, t := range report.ResourceTemplates {
		currentTemplates[t.URITemplate] = t
	}

	// Check for removed templates
	for uri := range lockedTemplates {
		if _, found := currentTemplates[uri]; !found {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftTemplateRemoved,
				Severity:   SeverityCritical,
				Identifier: uri,
				Message:    fmt.Sprintf("Template [%s] has been removed from the server", uri),
			})
		}
	}

	// Check for added or changed templates
	for _, template := range report.ResourceTemplates {
		locked, found := lockedTemplates[template.URITemplate]
		if !found {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftTemplateAdded,
				Severity:   SeverityCritical,
				Identifier: template.URITemplate,
				Message:    fmt.Sprintf("Template [%s] has been added to the server", template.URITemplate),
			})
			continue
		}

		// Check template hash
		currentHash, err := locker.HashTemplate(template.URITemplate, template.MimeType)
		if err != nil {
			return nil, fmt.Errorf("failed to hash template %s: %w", template.URITemplate, err)
		}

		if locked.TemplateHash != currentHash {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftTemplateChanged,
				Severity:   SeverityCritical,
				Identifier: template.URITemplate,
				OldHash:    locked.TemplateHash,
				NewHash:    currentHash,
				Message:    fmt.Sprintf("Template [%s] changed: %s → %s", template.URITemplate, truncHash(locked.TemplateHash), truncHash(currentHash)),
			})
		}
	}

	return drifts, nil
}

// compareTools helper
func compareTools(lockfile *models.LockfileV3, report *models.ScanReport) ([]V3DriftItem, error) {
	var drifts []V3DriftItem

	// Build map of current tools from scan
	currentTools := make(map[string]models.Tool)
	for _, t := range report.Tools {
		currentTools[t.Name] = t
	}

	// Check for removed tools
	for name := range lockfile.Tools {
		if _, found := currentTools[name]; !found {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftToolRemoved,
				Severity:   SeverityCritical,
				Identifier: name,
				Message:    fmt.Sprintf("Tool [%s] has been removed from the server", name),
			})
		}
	}

	// Check for added or changed tools
	for _, tool := range report.Tools {
		locked, found := lockfile.Tools[tool.Name]
		if !found {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftToolAdded,
				Severity:   SeverityCritical,
				Identifier: tool.Name,
				Message:    fmt.Sprintf("Tool [%s] has been added to the server", tool.Name),
			})
			continue
		}

		// Check description hash
		currentDescHash := locker.HashString(tool.Description)
		if locked.DescriptionHash != currentDescHash {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftToolChanged,
				Severity:   SeverityModerate,
				Identifier: tool.Name,
				OldHash:    locked.DescriptionHash,
				NewHash:    currentDescHash,
				Message:    fmt.Sprintf("Tool [%s] description changed", tool.Name),
			})
		}

		// Check schema hash
		currentSchemaHash, err := locker.HashJSON(tool.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("failed to hash schema for tool %s: %w", tool.Name, err)
		}
		if locked.InputSchemaHash != currentSchemaHash {
			drifts = append(drifts, V3DriftItem{
				Type:       V3DriftToolChanged,
				Severity:   SeverityCritical,
				Identifier: tool.Name,
				OldHash:    locked.InputSchemaHash,
				NewHash:    currentSchemaHash,
				Message:    fmt.Sprintf("Tool [%s] schema changed: %s → %s", tool.Name, truncHash(locked.InputSchemaHash), truncHash(currentSchemaHash)),
			})
		}
	}

	return drifts, nil
}

// truncHash helper
func truncHash(h string) string {
	if len(h) <= 20 {
		return h
	}
	return h[:20] + "..."
}

// FormatV3Drift helper
func FormatV3Drift(d V3DriftItem) string {
	return fmt.Sprintf("%s: %s", d.Type, d.Identifier)
}
