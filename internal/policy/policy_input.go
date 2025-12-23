package policy

import (
	"sort"
	"strings"

	"github.com/mcptrust/mcptrust/internal/differ"
	"github.com/mcptrust/mcptrust/internal/models"
)

// V3PolicyInput context for CEL
type V3PolicyInput struct {
	LockfileVersion string                   `json:"lockfileVersion"`
	Server          ServerInput              `json:"server"`
	Prompts         PromptsInput             `json:"prompts"`
	Resources       ResourcesInput           `json:"resources"`
	Drift           DriftInput               `json:"drift"`
	Tools           []map[string]interface{} `json:"tools"`
}

// ServerInput identity
type ServerInput struct {
	Name     string                 `json:"name"`
	Artifact map[string]interface{} `json:"artifact,omitempty"`
}

// PromptsInput data
type PromptsInput struct {
	Names       []string                         `json:"names"` // sorted list of prompt names
	Definitions map[string]PromptDefinitionInput `json:"definitions"`
}

// PromptDefinitionInput detail
type PromptDefinitionInput struct {
	ArgumentsHash string `json:"argumentsHash"`
}

// ResourcesInput templates
type ResourcesInput struct {
	Templates []TemplateInput `json:"templates"`
	Schemes   []string        `json:"schemes"` // sorted list of unique schemes
}

// TemplateInput detail
type TemplateInput struct {
	URITemplate  string `json:"uriTemplate"`
	MimeType     string `json:"mimeType,omitempty"`
	TemplateHash string `json:"templateHash"`
}

// DriftInput status
type DriftInput struct {
	HasDrift bool             `json:"hasDrift"`
	Items    []DriftItemInput `json:"items"`
}

// DriftItemInput detail
type DriftItemInput struct {
	Type     string `json:"type"`
	Severity string `json:"severity"` // "critical", "moderate", "info"
	ID       string `json:"id"`
	OldHash  string `json:"oldHash,omitempty"`
	NewHash  string `json:"newHash,omitempty"`
	Message  string `json:"message"`
}

// BuildV3PolicyInput from context (deterministic)
func BuildV3PolicyInput(lockfile *models.LockfileV3, report *models.ScanReport, drift *differ.V3Result) V3PolicyInput {
	input := V3PolicyInput{
		LockfileVersion: lockfile.LockFileVersion,
		Server:          buildServerInput(lockfile),
		Prompts:         buildPromptsInput(lockfile),
		Resources:       buildResourcesInput(lockfile),
		Drift:           buildDriftInput(drift),
		Tools:           buildToolsInput(report),
	}

	return input
}

// buildServerInput from lockfile
func buildServerInput(lockfile *models.LockfileV3) ServerInput {
	server := ServerInput{
		Name: lockfile.Server.Name,
	}
	if lockfile.Server.Artifact != nil {
		server.Artifact = artifactToMap(lockfile.Server.Artifact)
	}
	return server
}

// buildPromptsInput from lockfile
func buildPromptsInput(lockfile *models.LockfileV3) PromptsInput {
	names := make([]string, 0, len(lockfile.Prompts.Definitions))
	definitions := make(map[string]PromptDefinitionInput)

	for name, def := range lockfile.Prompts.Definitions {
		names = append(names, name)
		definitions[name] = PromptDefinitionInput{
			ArgumentsHash: def.ArgumentsHash,
		}
	}

	// Deterministic sort
	sort.Strings(names)

	return PromptsInput{
		Names:       names,
		Definitions: definitions,
	}
}

// buildResourcesInput from lockfile
func buildResourcesInput(lockfile *models.LockfileV3) ResourcesInput {
	templates := make([]TemplateInput, 0, len(lockfile.Resources.Templates))
	schemeSet := make(map[string]bool)

	for _, t := range lockfile.Resources.Templates {
		templates = append(templates, TemplateInput{
			URITemplate:  t.URITemplate,
			MimeType:     t.MimeType,
			TemplateHash: t.TemplateHash,
		})

		// Extract scheme
		if scheme := extractScheme(t.URITemplate); scheme != "" {
			schemeSet[scheme] = true
		}
	}

	// Sort templates by URITemplate
	sort.Slice(templates, func(i, j int) bool {
		return templates[i].URITemplate < templates[j].URITemplate
	})

	// Convert scheme set to sorted slice
	schemes := make([]string, 0, len(schemeSet))
	for scheme := range schemeSet {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)

	return ResourcesInput{
		Templates: templates,
		Schemes:   schemes,
	}
}

// extractScheme/protocol
func extractScheme(uriTemplate string) string {
	idx := strings.Index(uriTemplate, "://")
	if idx <= 0 {
		return ""
	}
	scheme := uriTemplate[:idx]
	// Basic validation (alpha, +, -, .)
	for _, c := range scheme {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
			return ""
		}
	}
	return strings.ToLower(scheme)
}

// buildDriftInput from result
func buildDriftInput(drift *differ.V3Result) DriftInput {
	if drift == nil {
		return DriftInput{
			HasDrift: false,
			Items:    []DriftItemInput{},
		}
	}

	items := make([]DriftItemInput, 0, len(drift.Drifts))
	for _, d := range drift.Drifts {
		items = append(items, DriftItemInput{
			Type:     string(d.Type),
			Severity: differ.SeverityString(d.Severity),
			ID:       d.Identifier,
			OldHash:  d.OldHash,
			NewHash:  d.NewHash,
			Message:  d.Message,
		})
	}

	return DriftInput{
		HasDrift: drift.HasDrift,
		Items:    items,
	}
}

// buildToolsInput from report
func buildToolsInput(report *models.ScanReport) []map[string]interface{} {
	tools := make([]map[string]interface{}, 0, len(report.Tools))
	for _, t := range report.Tools {
		tools = append(tools, map[string]interface{}{
			"name":         t.Name,
			"description":  t.Description,
			"input_schema": t.InputSchema,
			"risk_level":   string(t.RiskLevel),
		})
	}
	return tools
}

// ToMap for CEL
func (p *V3PolicyInput) ToMap() map[string]interface{} {
	// Build prompts map
	promptDefs := make(map[string]interface{})
	for name, def := range p.Prompts.Definitions {
		promptDefs[name] = map[string]interface{}{
			"argumentsHash": def.ArgumentsHash,
		}
	}

	// Build templates list
	templates := make([]interface{}, 0, len(p.Resources.Templates))
	for _, t := range p.Resources.Templates {
		templates = append(templates, map[string]interface{}{
			"uriTemplate":  t.URITemplate,
			"mimeType":     t.MimeType,
			"templateHash": t.TemplateHash,
		})
	}

	// Build drift items list
	driftItems := make([]interface{}, 0, len(p.Drift.Items))
	for _, d := range p.Drift.Items {
		driftItems = append(driftItems, map[string]interface{}{
			"type":     d.Type,
			"severity": d.Severity,
			"id":       d.ID,
			"oldHash":  d.OldHash,
			"newHash":  d.NewHash,
			"message":  d.Message,
		})
	}

	// Convert schemes to interface slice
	schemes := make([]interface{}, len(p.Resources.Schemes))
	for i, s := range p.Resources.Schemes {
		schemes[i] = s
	}

	// Convert prompt names to interface slice
	promptNames := make([]interface{}, len(p.Prompts.Names))
	for i, n := range p.Prompts.Names {
		promptNames[i] = n
	}

	result := map[string]interface{}{
		"lockfileVersion": p.LockfileVersion,
		"server": map[string]interface{}{
			"name":     p.Server.Name,
			"artifact": p.Server.Artifact,
		},
		"prompts": map[string]interface{}{
			"names":       promptNames,
			"definitions": promptDefs,
		},
		"resources": map[string]interface{}{
			"templates": templates,
			"schemes":   schemes,
		},
		"drift": map[string]interface{}{
			"hasDrift": p.Drift.HasDrift,
			"items":    driftItems,
		},
		"tools": p.Tools,
	}

	// Back-compat: expose artifact
	if p.Server.Artifact != nil {
		result["artifact"] = p.Server.Artifact
	}

	return result
}
