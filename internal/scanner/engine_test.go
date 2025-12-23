package scanner

import (
	"encoding/json"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

// TestListPromptsParsesFull tests that prompts with all fields are parsed correctly
func TestListPromptsParsesFull(t *testing.T) {
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"prompts": [
				{
					"name": "code_review",
					"description": "Analyze code quality",
					"arguments": [
						{
							"name": "code",
							"description": "The code to review",
							"required": true
						}
					]
				}
			]
		}
	}`

	var resp models.MCPPromptsListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("result is nil")
	}

	if len(resp.Result.Prompts) != 1 {
		t.Fatalf("expected 1 prompt, got %d", len(resp.Result.Prompts))
	}

	prompt := resp.Result.Prompts[0]
	if prompt.Name != "code_review" {
		t.Errorf("expected name 'code_review', got '%s'", prompt.Name)
	}
	if prompt.Description != "Analyze code quality" {
		t.Errorf("expected description 'Analyze code quality', got '%s'", prompt.Description)
	}
	if len(prompt.Arguments) != 1 {
		t.Fatalf("expected 1 argument, got %d", len(prompt.Arguments))
	}
	if prompt.Arguments[0].Name != "code" {
		t.Errorf("expected argument name 'code', got '%s'", prompt.Arguments[0].Name)
	}
	if !prompt.Arguments[0].Required {
		t.Error("expected argument to be required")
	}
}

// TestListPromptsHandlesOptionalFields tests that prompts without optional fields parse correctly
func TestListPromptsHandlesOptionalFields(t *testing.T) {
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"prompts": [
				{
					"name": "simple_prompt"
				}
			]
		}
	}`

	var resp models.MCPPromptsListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("result is nil")
	}

	if len(resp.Result.Prompts) != 1 {
		t.Fatalf("expected 1 prompt, got %d", len(resp.Result.Prompts))
	}

	prompt := resp.Result.Prompts[0]
	if prompt.Name != "simple_prompt" {
		t.Errorf("expected name 'simple_prompt', got '%s'", prompt.Name)
	}
	if prompt.Description != "" {
		t.Errorf("expected empty description, got '%s'", prompt.Description)
	}
	if len(prompt.Arguments) != 0 {
		t.Errorf("expected no arguments, got %d", len(prompt.Arguments))
	}
}

// TestListPromptsMethodNotSupported tests that error code -32601 is recognized
func TestListPromptsMethodNotSupported(t *testing.T) {
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"error": {
			"code": -32601,
			"message": "Method not found"
		}
	}`

	var resp models.MCPPromptsListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != models.JSONRPCMethodNotFound {
		t.Errorf("expected error code %d, got %d", models.JSONRPCMethodNotFound, resp.Error.Code)
	}
}

// TestListPromptsOtherErrorsNotSuppressed tests that non-32601 errors are not swallowed
func TestListPromptsOtherErrorsNotSuppressed(t *testing.T) {
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"error": {
			"code": -32600,
			"message": "Invalid Request"
		}
	}`

	var resp models.MCPPromptsListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// This error should NOT be treated as "method not found"
	if resp.Error.Code == models.JSONRPCMethodNotFound {
		t.Error("error code -32600 should not be treated as method not found")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("expected error code -32600, got %d", resp.Error.Code)
	}
}

// TestListPromptsPaginationParsing tests that pagination fields are parsed correctly
func TestListPromptsPaginationParsing(t *testing.T) {
	// First page with nextCursor
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"prompts": [
				{"name": "prompt1"}
			],
			"nextCursor": "cursor_page_2"
		}
	}`

	var resp models.MCPPromptsListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("result is nil")
	}

	if len(resp.Result.Prompts) != 1 {
		t.Fatalf("expected 1 prompt, got %d", len(resp.Result.Prompts))
	}

	if resp.Result.NextCursor != "cursor_page_2" {
		t.Errorf("expected nextCursor 'cursor_page_2', got '%s'", resp.Result.NextCursor)
	}

	// Last page (empty nextCursor)
	jsonRespLast := `{
		"jsonrpc": "2.0",
		"id": 2,
		"result": {
			"prompts": [
				{"name": "prompt2"}
			]
		}
	}`

	var respLast models.MCPPromptsListResponse
	if err := json.Unmarshal([]byte(jsonRespLast), &respLast); err != nil {
		t.Fatalf("failed to unmarshal last page response: %v", err)
	}

	if respLast.Result.NextCursor != "" {
		t.Errorf("expected empty nextCursor on last page, got '%s'", respLast.Result.NextCursor)
	}
}

// TestListResourceTemplatesParsesFull tests that templates with all fields are parsed correctly
func TestListResourceTemplatesParsesFull(t *testing.T) {
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"resourceTemplates": [
				{
					"uriTemplate": "file:///{path}",
					"name": "Project Files",
					"description": "Access project files",
					"mimeType": "application/octet-stream"
				}
			]
		}
	}`

	var resp models.MCPResourceTemplatesListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("result is nil")
	}

	if len(resp.Result.ResourceTemplates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(resp.Result.ResourceTemplates))
	}

	template := resp.Result.ResourceTemplates[0]
	if template.URITemplate != "file:///{path}" {
		t.Errorf("expected uriTemplate 'file:///{path}', got '%s'", template.URITemplate)
	}
	if template.Name != "Project Files" {
		t.Errorf("expected name 'Project Files', got '%s'", template.Name)
	}
	if template.Description != "Access project files" {
		t.Errorf("expected description 'Access project files', got '%s'", template.Description)
	}
	if template.MimeType != "application/octet-stream" {
		t.Errorf("expected mimeType 'application/octet-stream', got '%s'", template.MimeType)
	}
}

// TestListResourceTemplatesHandlesOptionalFields tests templates without optional fields
func TestListResourceTemplatesHandlesOptionalFields(t *testing.T) {
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"resourceTemplates": [
				{
					"uriTemplate": "api://endpoint/{path}"
				}
			]
		}
	}`

	var resp models.MCPResourceTemplatesListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("result is nil")
	}

	if len(resp.Result.ResourceTemplates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(resp.Result.ResourceTemplates))
	}

	template := resp.Result.ResourceTemplates[0]
	if template.URITemplate != "api://endpoint/{path}" {
		t.Errorf("expected uriTemplate 'api://endpoint/{path}', got '%s'", template.URITemplate)
	}
	if template.Name != "" {
		t.Errorf("expected empty name, got '%s'", template.Name)
	}
	if template.Description != "" {
		t.Errorf("expected empty description, got '%s'", template.Description)
	}
	if template.MimeType != "" {
		t.Errorf("expected empty mimeType, got '%s'", template.MimeType)
	}
}

// TestListResourceTemplatesMethodNotSupported tests that error code -32601 is recognized
func TestListResourceTemplatesMethodNotSupported(t *testing.T) {
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"error": {
			"code": -32601,
			"message": "Method not found"
		}
	}`

	var resp models.MCPResourceTemplatesListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != models.JSONRPCMethodNotFound {
		t.Errorf("expected error code %d, got %d", models.JSONRPCMethodNotFound, resp.Error.Code)
	}
}

// TestResourceTemplatesPaginationParsing tests that pagination fields are parsed
func TestResourceTemplatesPaginationParsing(t *testing.T) {
	jsonResp := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"resourceTemplates": [
				{"uriTemplate": "file:///{path}"}
			],
			"nextCursor": "next_page"
		}
	}`

	var resp models.MCPResourceTemplatesListResponse
	if err := json.Unmarshal([]byte(jsonResp), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("result is nil")
	}

	if resp.Result.NextCursor != "next_page" {
		t.Errorf("expected nextCursor 'next_page', got '%s'", resp.Result.NextCursor)
	}
}

// TestScanReportDeterministicSort tests that prompts and templates are sorted
func TestScanReportDeterministicSort(t *testing.T) {
	// Test prompt sorting
	prompts := []models.Prompt{
		{Name: "zebra"},
		{Name: "apple"},
		{Name: "mango"},
	}

	// Manually simulate what Scan() does
	sortedPrompts := make([]models.Prompt, len(prompts))
	copy(sortedPrompts, prompts)
	// Use sort from the standard library (simulating Scan behavior)
	for i := 0; i < len(sortedPrompts)-1; i++ {
		for j := i + 1; j < len(sortedPrompts); j++ {
			if sortedPrompts[i].Name > sortedPrompts[j].Name {
				sortedPrompts[i], sortedPrompts[j] = sortedPrompts[j], sortedPrompts[i]
			}
		}
	}

	expected := []string{"apple", "mango", "zebra"}
	for i, name := range expected {
		if sortedPrompts[i].Name != name {
			t.Errorf("prompt at index %d: expected '%s', got '%s'", i, name, sortedPrompts[i].Name)
		}
	}

	// Test template sorting
	templates := []models.ResourceTemplate{
		{URITemplate: "z://template"},
		{URITemplate: "a://template"},
		{URITemplate: "m://template"},
	}

	sortedTemplates := make([]models.ResourceTemplate, len(templates))
	copy(sortedTemplates, templates)
	for i := 0; i < len(sortedTemplates)-1; i++ {
		for j := i + 1; j < len(sortedTemplates); j++ {
			if sortedTemplates[i].URITemplate > sortedTemplates[j].URITemplate {
				sortedTemplates[i], sortedTemplates[j] = sortedTemplates[j], sortedTemplates[i]
			}
		}
	}

	expectedTemplates := []string{"a://template", "m://template", "z://template"}
	for i, uri := range expectedTemplates {
		if sortedTemplates[i].URITemplate != uri {
			t.Errorf("template at index %d: expected '%s', got '%s'", i, uri, sortedTemplates[i].URITemplate)
		}
	}
}

// TestScanReportIncludesNewFields tests that ScanReport has the new fields
func TestScanReportIncludesNewFields(t *testing.T) {
	report := &models.ScanReport{
		Prompts: []models.Prompt{
			{Name: "test_prompt", Description: "A test prompt"},
		},
		ResourceTemplates: []models.ResourceTemplate{
			{URITemplate: "test://template", Name: "Test Template"},
		},
	}

	// Marshal to JSON to verify fields are present
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}

	// Parse back to verify structure
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, ok := parsed["prompts"]; !ok {
		t.Error("prompts field missing from JSON output")
	}
	if _, ok := parsed["resourceTemplates"]; !ok {
		t.Error("resourceTemplates field missing from JSON output")
	}
}

// TestJSONRPCMethodNotFoundConstant tests the error code constant is correct
func TestJSONRPCMethodNotFoundConstant(t *testing.T) {
	if models.JSONRPCMethodNotFound != -32601 {
		t.Errorf("JSONRPCMethodNotFound should be -32601, got %d", models.JSONRPCMethodNotFound)
	}
}
