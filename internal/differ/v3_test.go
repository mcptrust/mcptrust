package differ

import (
	"testing"

	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/models"
)

func TestCompareV3_NoChange(t *testing.T) {
	lockfile := &models.LockfileV3{
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{
				"test_prompt": {ArgumentsHash: "sha256:abc123"},
			},
		},
		Resources: models.ResourcesSection{
			Templates: []models.ResourceTemplateLock{
				{URITemplate: "file:///{path}", TemplateHash: "sha256:def456"},
			},
		},
		Tools: map[string]models.ToolLock{
			"test_tool": {DescriptionHash: "sha256:tool123", InputSchemaHash: ""},
		},
	}

	// Build matching report
	report := &models.ScanReport{
		Prompts: []models.Prompt{
			{Name: "test_prompt", Arguments: nil}, // same as hash
		},
		ResourceTemplates: []models.ResourceTemplate{
			{URITemplate: "file:///{path}"}, // same as hash
		},
		Tools: []models.Tool{
			{Name: "test_tool", Description: ""}, // empty desc matches hash
		},
	}

	// Compute expected hashes to build matching lockfile
	argsHash, _ := locker.HashPromptArguments(nil)
	templateHash, _ := locker.HashTemplate("file:///{path}", "")
	descHash := locker.HashString("")

	lockfile.Prompts.Definitions["test_prompt"] = models.PromptDefinition{
		ArgumentsHash: argsHash,
	}
	lockfile.Resources.Templates[0].TemplateHash = templateHash
	lockfile.Tools["test_tool"] = models.ToolLock{
		DescriptionHash: descHash,
		InputSchemaHash: "",
	}

	result, err := CompareV3(lockfile, report)
	if err != nil {
		t.Fatalf("CompareV3 failed: %v", err)
	}

	if result.HasDrift {
		t.Errorf("expected no drift, got %d changes", len(result.Drifts))
		for _, d := range result.Drifts {
			t.Logf("  drift: %s %s", d.Type, d.Identifier)
		}
	}
}

func TestCompareV3_PromptAdded(t *testing.T) {
	lockfile := &models.LockfileV3{
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{},
		},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
		Tools:     map[string]models.ToolLock{},
	}

	report := &models.ScanReport{
		Prompts: []models.Prompt{
			{Name: "new_prompt"},
		},
	}

	result, err := CompareV3(lockfile, report)
	if err != nil {
		t.Fatalf("CompareV3 failed: %v", err)
	}

	if !result.HasDrift {
		t.Fatal("expected drift for added prompt")
	}

	found := false
	for _, d := range result.Drifts {
		if d.Type == V3DriftPromptAdded && d.Identifier == "new_prompt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PROMPT_ADDED: new_prompt")
	}
}

func TestCompareV3_PromptArgsChanged(t *testing.T) {
	// Create lockfile with specific args hash
	oldArgsHash, _ := locker.HashPromptArguments([]models.PromptArgument{
		{Name: "old_arg", Required: true},
	})

	lockfile := &models.LockfileV3{
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{
				"test_prompt": {ArgumentsHash: oldArgsHash},
			},
		},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
		Tools:     map[string]models.ToolLock{},
	}

	// Report has different args
	report := &models.ScanReport{
		Prompts: []models.Prompt{
			{
				Name: "test_prompt",
				Arguments: []models.PromptArgument{
					{Name: "new_arg", Required: false},
				},
			},
		},
	}

	result, err := CompareV3(lockfile, report)
	if err != nil {
		t.Fatalf("CompareV3 failed: %v", err)
	}

	if !result.HasDrift {
		t.Fatal("expected drift for changed args")
	}

	found := false
	for _, d := range result.Drifts {
		if d.Type == V3DriftPromptArgsChanged && d.Identifier == "test_prompt" {
			found = true
			if d.OldHash == "" || d.NewHash == "" {
				t.Error("expected old and new hash in drift item")
			}
			break
		}
	}
	if !found {
		t.Error("expected PROMPT_ARGS_CHANGED: test_prompt")
	}
}

func TestCompareV3_TemplateAdded(t *testing.T) {
	lockfile := &models.LockfileV3{
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
		Tools:     map[string]models.ToolLock{},
	}

	report := &models.ScanReport{
		ResourceTemplates: []models.ResourceTemplate{
			{URITemplate: "new://template"},
		},
	}

	result, err := CompareV3(lockfile, report)
	if err != nil {
		t.Fatalf("CompareV3 failed: %v", err)
	}

	if !result.HasDrift {
		t.Fatal("expected drift for added template")
	}

	found := false
	for _, d := range result.Drifts {
		if d.Type == V3DriftTemplateAdded && d.Identifier == "new://template" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TEMPLATE_ADDED: new://template")
	}
}

func TestCompareV3_TemplateChanged(t *testing.T) {
	oldHash, _ := locker.HashTemplate("file:///{path}", "text/plain")

	lockfile := &models.LockfileV3{
		Prompts: models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{
			Templates: []models.ResourceTemplateLock{
				{URITemplate: "file:///{path}", TemplateHash: oldHash},
			},
		},
		Tools: map[string]models.ToolLock{},
	}

	// Report has different mimeType
	report := &models.ScanReport{
		ResourceTemplates: []models.ResourceTemplate{
			{URITemplate: "file:///{path}", MimeType: "application/json"},
		},
	}

	result, err := CompareV3(lockfile, report)
	if err != nil {
		t.Fatalf("CompareV3 failed: %v", err)
	}

	if !result.HasDrift {
		t.Fatal("expected drift for changed template")
	}

	found := false
	for _, d := range result.Drifts {
		if d.Type == V3DriftTemplateChanged && d.Identifier == "file:///{path}" {
			found = true
			if d.OldHash == "" || d.NewHash == "" {
				t.Error("expected old and new hash in drift item")
			}
			break
		}
	}
	if !found {
		t.Error("expected TEMPLATE_CHANGED: file:///{path}")
	}
}

func TestCompareV3_ToolAdded(t *testing.T) {
	lockfile := &models.LockfileV3{
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
		Tools:     map[string]models.ToolLock{},
	}

	report := &models.ScanReport{
		Tools: []models.Tool{
			{Name: "new_tool", Description: "New"},
		},
	}

	result, err := CompareV3(lockfile, report)
	if err != nil {
		t.Fatalf("CompareV3 failed: %v", err)
	}

	if !result.HasDrift {
		t.Fatal("expected drift for added tool")
	}

	found := false
	for _, d := range result.Drifts {
		if d.Type == V3DriftToolAdded && d.Identifier == "new_tool" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TOOL_ADDED: new_tool")
	}
}

func TestCompareV3_PromptRemoved(t *testing.T) {
	argsHash, _ := locker.HashPromptArguments(nil)

	lockfile := &models.LockfileV3{
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{
				"removed_prompt": {ArgumentsHash: argsHash},
			},
		},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
		Tools:     map[string]models.ToolLock{},
	}

	// Empty report - prompt was removed
	report := &models.ScanReport{
		Prompts: []models.Prompt{},
	}

	result, err := CompareV3(lockfile, report)
	if err != nil {
		t.Fatalf("CompareV3 failed: %v", err)
	}

	if !result.HasDrift {
		t.Fatal("expected drift for removed prompt")
	}

	found := false
	for _, d := range result.Drifts {
		if d.Type == V3DriftPromptRemoved && d.Identifier == "removed_prompt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PROMPT_REMOVED: removed_prompt")
	}
}

func TestFormatV3Drift(t *testing.T) {
	drift := V3DriftItem{
		Type:       V3DriftPromptAdded,
		Identifier: "test_prompt",
	}

	formatted := FormatV3Drift(drift)
	if formatted != "PROMPT_ADDED: test_prompt" {
		t.Errorf("unexpected format: %s", formatted)
	}
}
