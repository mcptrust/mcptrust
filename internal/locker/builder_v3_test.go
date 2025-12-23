package locker

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

// TestBuilderV3Build tests basic lockfile creation
func TestBuilderV3Build(t *testing.T) {
	report := &models.ScanReport{
		ServerInfo: &models.ServerInfo{
			Name:            "test-server",
			Version:         "1.0.0",
			ProtocolVersion: "2024-11-05",
		},
		Prompts: []models.Prompt{
			{
				Name:        "code_review",
				Description: "Review code quality",
				Arguments: []models.PromptArgument{
					{Name: "code", Required: true},
				},
			},
			{
				Name:        "summarize",
				Description: "Summarize text",
			},
		},
		ResourceTemplates: []models.ResourceTemplate{
			{
				URITemplate: "file:///{path}",
				Name:        "Files",
				Description: "File access",
				MimeType:    "application/octet-stream",
			},
		},
		Tools: []models.Tool{
			{
				Name:        "read_file",
				Description: "Read file contents",
				RiskLevel:   models.RiskLevelLow,
			},
		},
	}

	builder := NewBuilderV3()
	lockfile, err := builder.Build(report)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Check version
	if lockfile.LockFileVersion != models.LockfileV3Version {
		t.Errorf("expected version %s, got %s", models.LockfileV3Version, lockfile.LockFileVersion)
	}

	// Check server name
	if lockfile.Server.Name != "test-server" {
		t.Errorf("expected server name 'test-server', got %s", lockfile.Server.Name)
	}

	// Check prompts
	if len(lockfile.Prompts.Definitions) != 2 {
		t.Errorf("expected 2 prompts, got %d", len(lockfile.Prompts.Definitions))
	}
	if _, ok := lockfile.Prompts.Definitions["code_review"]; !ok {
		t.Error("expected code_review prompt")
	}
	if _, ok := lockfile.Prompts.Definitions["summarize"]; !ok {
		t.Error("expected summarize prompt")
	}

	// Check templates
	if len(lockfile.Resources.Templates) != 1 {
		t.Errorf("expected 1 template, got %d", len(lockfile.Resources.Templates))
	}
	if lockfile.Resources.Templates[0].URITemplate != "file:///{path}" {
		t.Errorf("expected template 'file:///{path}', got %s", lockfile.Resources.Templates[0].URITemplate)
	}

	// Check tools
	if len(lockfile.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(lockfile.Tools))
	}
}

// TestBuilderV3PromptsSorted tests that prompts are keyed correctly
func TestBuilderV3PromptsSorted(t *testing.T) {
	report := &models.ScanReport{
		Prompts: []models.Prompt{
			{Name: "zebra"},
			{Name: "apple"},
			{Name: "mango"},
		},
	}

	builder := NewBuilderV3()
	lockfile, err := builder.Build(report)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// All prompts should be present
	for _, name := range []string{"apple", "mango", "zebra"} {
		if _, ok := lockfile.Prompts.Definitions[name]; !ok {
			t.Errorf("expected prompt %s", name)
		}
	}
}

// TestBuilderV3TemplatesSorted tests that templates are sorted by URI
func TestBuilderV3TemplatesSorted(t *testing.T) {
	report := &models.ScanReport{
		ResourceTemplates: []models.ResourceTemplate{
			{URITemplate: "z://template"},
			{URITemplate: "a://template"},
			{URITemplate: "m://template"},
		},
	}

	builder := NewBuilderV3()
	lockfile, err := builder.Build(report)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Check order
	expected := []string{"a://template", "m://template", "z://template"}
	for i, uri := range expected {
		if lockfile.Resources.Templates[i].URITemplate != uri {
			t.Errorf("template %d: expected %s, got %s", i, uri, lockfile.Resources.Templates[i].URITemplate)
		}
	}
}

// TestBuilderV3HashesNotEmpty tests that hashes are populated
func TestBuilderV3HashesNotEmpty(t *testing.T) {
	report := &models.ScanReport{
		Prompts: []models.Prompt{
			{
				Name:        "test",
				Description: "Test prompt",
				Arguments: []models.PromptArgument{
					{Name: "arg1", Required: true},
				},
			},
		},
		ResourceTemplates: []models.ResourceTemplate{
			{
				URITemplate: "file:///{path}",
				Name:        "Files",
				Description: "Access files",
			},
		},
	}

	builder := NewBuilderV3()
	lockfile, err := builder.Build(report)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Check prompt hashes
	prompt := lockfile.Prompts.Definitions["test"]
	if prompt.ArgumentsHash == "" {
		t.Error("expected non-empty argumentsHash")
	}
	if prompt.DescriptionHash == "" {
		t.Error("expected non-empty descriptionHash")
	}

	// Check template hashes
	template := lockfile.Resources.Templates[0]
	if template.TemplateHash == "" {
		t.Error("expected non-empty templateHash")
	}
	if template.NameHash == "" {
		t.Error("expected non-empty nameHash")
	}
	if template.DescriptionHash == "" {
		t.Error("expected non-empty descriptionHash")
	}
}

// TestBuilderV3Determinism tests that repeated builds produce same hashes
func TestBuilderV3Determinism(t *testing.T) {
	report := &models.ScanReport{
		ServerInfo: &models.ServerInfo{Name: "test"},
		Prompts: []models.Prompt{
			{Name: "prompt1", Arguments: []models.PromptArgument{{Name: "a"}, {Name: "b"}}},
		},
		ResourceTemplates: []models.ResourceTemplate{
			{URITemplate: "test://{id}", MimeType: "text/plain"},
		},
	}

	builder := NewBuilderV3()

	lockfile1, err := builder.Build(report)
	if err != nil {
		t.Fatalf("Build 1 failed: %v", err)
	}

	lockfile2, err := builder.Build(report)
	if err != nil {
		t.Fatalf("Build 2 failed: %v", err)
	}

	// Compare prompt hashes
	if lockfile1.Prompts.Definitions["prompt1"].ArgumentsHash !=
		lockfile2.Prompts.Definitions["prompt1"].ArgumentsHash {
		t.Error("prompt argumentsHash differs between builds")
	}

	// Compare template hashes
	if lockfile1.Resources.Templates[0].TemplateHash !=
		lockfile2.Resources.Templates[0].TemplateHash {
		t.Error("template hash differs between builds")
	}
}

// TestBuilderV3GoldenFile tests against golden fixture (if exists)
func TestBuilderV3GoldenFile(t *testing.T) {
	goldenPath := "../../testdata/golden/mcp-lock.v3.json"

	// Skip if golden doesn't exist yet
	if _, err := os.Stat(goldenPath); os.IsNotExist(err) {
		t.Skip("golden file not found, run 'go generate' to create")
	}

	goldenData, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file: %v", err)
	}

	var goldenLockfile models.LockfileV3
	if err := json.Unmarshal(goldenData, &goldenLockfile); err != nil {
		t.Fatalf("failed to parse golden file: %v", err)
	}

	// Build from fixture prompts/templates
	report := &models.ScanReport{
		ServerInfo: &models.ServerInfo{Name: "test-server"},
		Prompts: []models.Prompt{
			{
				Name:        "code_review",
				Description: "Asks the LLM to analyze code quality and suggest improvements",
				Arguments: []models.PromptArgument{
					{Name: "code", Description: "The code to review", Required: true},
				},
			},
			{
				Name:        "summarize",
				Description: "Summarize the given text",
			},
			{
				Name:        "translate",
				Description: "Translate text to another language",
				Arguments: []models.PromptArgument{
					{Name: "target_language", Description: "Target language code", Required: true},
					{Name: "text", Description: "The text to translate", Required: true},
				},
			},
		},
		ResourceTemplates: []models.ResourceTemplate{
			{URITemplate: "api://endpoint/{endpoint_path}", Name: "API Endpoints"},
			{URITemplate: "db://table/{table_name}", Name: "Database Tables", Description: "Access database table contents"},
			{URITemplate: "file:///{path}", Name: "Project Files", Description: "Access files in the project directory", MimeType: "application/octet-stream"},
		},
	}

	builder := NewBuilderV3()
	lockfile, err := builder.Build(report)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Compare prompt hashes
	for name, goldenDef := range goldenLockfile.Prompts.Definitions {
		builtDef, ok := lockfile.Prompts.Definitions[name]
		if !ok {
			t.Errorf("missing prompt: %s", name)
			continue
		}
		if goldenDef.ArgumentsHash != builtDef.ArgumentsHash {
			t.Errorf("prompt %s argumentsHash mismatch:\ngolden: %s\nbuilt:  %s",
				name, goldenDef.ArgumentsHash, builtDef.ArgumentsHash)
		}
	}

	// Compare template hashes
	goldenTemplates := make(map[string]models.ResourceTemplateLock)
	for _, t := range goldenLockfile.Resources.Templates {
		goldenTemplates[t.URITemplate] = t
	}

	for _, tmpl := range lockfile.Resources.Templates {
		golden, ok := goldenTemplates[tmpl.URITemplate]
		if !ok {
			t.Errorf("extra template: %s", tmpl.URITemplate)
			continue
		}
		if golden.TemplateHash != tmpl.TemplateHash {
			t.Errorf("template %s hash mismatch:\ngolden: %s\nbuilt:  %s",
				tmpl.URITemplate, golden.TemplateHash, tmpl.TemplateHash)
		}
	}
}
