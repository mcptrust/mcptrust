//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/models"
)

// Generates golden lockfile from test fixtures
func main() {
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

	builder := locker.NewBuilderV3()
	lockfile, err := builder.Build(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Build failed: %v\n", err)
		os.Exit(1)
	}

	// Override meta for reproducibility
	lockfile.Meta.Generator = "mcptrust test"
	lockfile.Meta.UpdatedAt = "2024-01-01T00:00:00Z"

	data, err := json.MarshalIndent(lockfile, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("testdata/golden/mcp-lock.v3.json", data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Write failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Golden file generated: testdata/golden/mcp-lock.v3.json")
}
