package proxy

import (
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

func TestCompileTemplateMatcher_BasicPlaceholder(t *testing.T) {
	tests := []struct {
		name     string
		template string
		input    string
		want     bool
	}{
		{
			name:     "db template matches db URI",
			template: "db://{id}",
			input:    "db://12345",
			want:     true,
		},
		{
			name:     "db template does not match file URI",
			template: "db://{id}",
			input:    "file:///tmp/test.txt",
			want:     false,
		},
		{
			name:     "file template matches file URI",
			template: "file:///{path}",
			input:    "file:///tmp",
			want:     true,
		},
		{
			name:     "file template does not match http URI",
			template: "file:///{path}",
			input:    "http://example.com",
			want:     false,
		},
		{
			name:     "multi-segment path matches single placeholder",
			template: "file:///{path}",
			input:    "file:///a", // single segment
			want:     true,
		},
		{
			name:     "multi-segment path DOES match final placeholder (uses .+)",
			template: "file:///{path}",
			input:    "file:///a/b/c",
			want:     true, // final placeholder uses (.+) for multi-segment paths
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := CompileTemplateMatcher(tt.template)
			if err != nil {
				t.Fatalf("CompileTemplateMatcher() error = %v", err)
			}
			got := matcher.MatchString(tt.input)
			if got != tt.want {
				t.Errorf("matcher.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCompileTemplateMatcher_UnsupportedOperators(t *testing.T) {
	unsupportedTemplates := []string{
		"file://{+path}",
		"api://{?query}",
		"uri://{#fragment}",
		"path://{.ext}",
		"multi://{/segments}",
		"matrix://{;params}",
		"form://{&query}",
	}

	for _, template := range unsupportedTemplates {
		t.Run(template, func(t *testing.T) {
			_, err := CompileTemplateMatcher(template)
			if err == nil {
				t.Errorf("expected error for unsupported template %q", template)
			}
		})
	}
}

func TestEnforcer_AllowTool(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools: map[string]models.ToolLock{
			"safe_tool":    {},
			"another_tool": {},
		},
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{},
		},
		Resources: models.ResourcesSection{
			Templates: []models.ResourceTemplateLock{},
		},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	tests := []struct {
		name string
		tool string
		want bool
	}{
		{"allowed tool", "safe_tool", true},
		{"another allowed tool", "another_tool", true},
		{"unknown tool", "debug_exec", false},
		{"empty tool name", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := enforcer.AllowTool(tt.tool)
			if got != tt.want {
				t.Errorf("AllowTool(%q) = %v, want %v", tt.tool, got, tt.want)
			}
		})
	}
}

func TestEnforcer_AllowPrompt(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools: map[string]models.ToolLock{},
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{
				"safe_prompt": {},
			},
		},
		Resources: models.ResourcesSection{
			Templates: []models.ResourceTemplateLock{},
		},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	tests := []struct {
		name   string
		prompt string
		want   bool
	}{
		{"allowed prompt", "safe_prompt", true},
		{"unknown prompt", "evil_prompt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := enforcer.AllowPrompt(tt.prompt)
			if got != tt.want {
				t.Errorf("AllowPrompt(%q) = %v, want %v", tt.prompt, got, tt.want)
			}
		})
	}
}

func TestEnforcer_AllowResourceURI(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools: map[string]models.ToolLock{},
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{},
		},
		Resources: models.ResourcesSection{
			Templates: []models.ResourceTemplateLock{
				{URITemplate: "db://{id}"},
			},
		},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{"matches db template", "db://12345", true},
		{"matches db with uuid", "db://abc-def-123", true},
		{"file URI not allowed", "file:///etc/passwd", false},
		{"http URI not allowed", "http://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := enforcer.AllowResourceURI(tt.uri)
			if got != tt.want {
				t.Errorf("AllowResourceURI(%q) = %v, want %v", tt.uri, got, tt.want)
			}
		})
	}
}

func TestEnforcer_StaticResources(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:   map[string]models.ToolLock{},
		Prompts: models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{
			Templates: []models.ResourceTemplateLock{
				{URITemplate: "db://{id}"},
			},
		},
	}

	enforcer, err := NewEnforcer(lockfile, true)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	// Initially, static resource not allowed
	if enforcer.AllowResourceURI("static://config.json") {
		t.Error("static://config.json should not be allowed before SetStaticResources")
	}

	// Add static resources
	enforcer.SetStaticResources([]string{"static://config.json"})

	// Now static resource should be allowed
	if !enforcer.AllowResourceURI("static://config.json") {
		t.Error("static://config.json should be allowed after SetStaticResources")
	}

	// Template matching still works
	if !enforcer.AllowResourceURI("db://123") {
		t.Error("db://123 should still match template")
	}
}

func TestDenyError(t *testing.T) {
	resp := DenyError(42, "tool not allowed")

	if resp["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", resp["jsonrpc"])
	}
	if resp["id"] != 42 {
		t.Errorf("id = %v, want 42", resp["id"])
	}

	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("error should be a map")
	}
	if errObj["code"] != MCPTrustDeniedCode {
		t.Errorf("error.code = %v, want %v", errObj["code"], MCPTrustDeniedCode)
	}
	if errObj["message"] != "MCPTRUST_DENIED: tool not allowed" {
		t.Errorf("error.message = %v", errObj["message"])
	}
}
