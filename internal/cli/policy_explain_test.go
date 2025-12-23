package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/policy"
)

func TestPolicyExplain_JSON(t *testing.T) {
	// Test JSON output with strict preset
	config := policy.GetPreset("strict")
	if config == nil {
		t.Fatal("strict preset not found")
	}

	source := ExplainSource{Type: "preset", Name: "strict"}
	output, err := generateExplainJSON(config, source)
	if err != nil {
		t.Fatalf("generateExplainJSON failed: %v", err)
	}

	// Parse and validate JSON structure
	var result ExplainOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	// Check schema version
	if result.SchemaVersion != "1.0" {
		t.Errorf("schema_version = %q, want %q", result.SchemaVersion, "1.0")
	}

	// Check source
	if result.Source.Type != "preset" {
		t.Errorf("source.type = %q, want %q", result.Source.Type, "preset")
	}
	if result.Source.Name != "strict" {
		t.Errorf("source.name = %q, want %q", result.Source.Name, "strict")
	}

	// Check generated_at is present
	if result.GeneratedAt == "" {
		t.Error("generated_at should not be empty")
	}

	// Check rules exist
	if len(result.Rules) == 0 {
		t.Error("rules should not be empty")
	}

	// Check at least one rule has control_refs (from updated preset)
	hasControlRefs := false
	for _, rule := range result.Rules {
		if len(rule.ControlRefs) > 0 {
			hasControlRefs = true
			break
		}
	}
	if !hasControlRefs {
		t.Error("at least one rule should have control_refs")
	}
}

func TestPolicyExplain_Markdown(t *testing.T) {
	// Test Markdown output with baseline preset
	config := policy.GetPreset("baseline")
	if config == nil {
		t.Fatal("baseline preset not found")
	}

	source := ExplainSource{Type: "preset", Name: "baseline"}
	output, err := generateExplainMarkdown(config, source)
	if err != nil {
		t.Fatalf("generateExplainMarkdown failed: %v", err)
	}

	// Check header row is present
	if !strings.Contains(output, "| Rule | Severity | Control Refs |") {
		t.Error("markdown should contain table header")
	}

	// Check at least one rule name is present
	hasRuleName := false
	for _, rule := range config.Rules {
		if strings.Contains(output, rule.Name) {
			hasRuleName = true
			break
		}
	}
	if !hasRuleName {
		t.Error("markdown should contain rule names")
	}

	// Check policy name in header
	if !strings.Contains(output, config.Name) {
		t.Errorf("markdown should contain policy name %q", config.Name)
	}
}

func TestPolicyExplain_TruncateExpr(t *testing.T) {
	tests := []struct {
		name   string
		expr   string
		maxLen int
		want   string
	}{
		{
			name:   "short expr unchanged",
			expr:   "size(input.tools) > 0",
			maxLen: 120,
			want:   "size(input.tools) > 0",
		},
		{
			name:   "long expr truncated",
			expr:   strings.Repeat("a", 150),
			maxLen: 120,
			want:   strings.Repeat("a", 119) + "…",
		},
		{
			name:   "multiline collapsed",
			expr:   "has(input.artifact)\n&& input.artifact.integrity != \"\"",
			maxLen: 120,
			want:   "has(input.artifact) && input.artifact.integrity != \"\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateExpr(tt.expr, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateExpr(%q, %d) = %q, want %q", tt.expr, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestPolicyExplain_FormatSlice(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		want  string
	}{
		{"nil slice", nil, "-"},
		{"empty slice", []string{}, "-"},
		{"single item", []string{"NIST AI RMF: GOVERN 1.1"}, "NIST AI RMF: GOVERN 1.1"},
		{"multiple items", []string{"A", "B", "C"}, "A, B, C"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatSliceForMD(tt.items)
			if got != tt.want {
				t.Errorf("formatSliceForMD(%v) = %q, want %q", tt.items, got, tt.want)
			}
		})
	}
}

func TestPolicyExplain_JSONNilSlicesAsEmptyArrays(t *testing.T) {
	// Rules without metadata should produce empty arrays, not null
	config := &models.PolicyConfig{
		Name: "Test",
		Rules: []models.PolicyRule{
			{
				Name:       "test_rule",
				Expr:       "true",
				FailureMsg: "Test",
				// Note: ControlRefs, Evidence, EvidenceCommands are nil
			},
		},
	}

	source := ExplainSource{Type: "file", Name: "test.yaml"}
	output, err := generateExplainJSON(config, source)
	if err != nil {
		t.Fatalf("generateExplainJSON failed: %v", err)
	}

	// Should have empty arrays, not null
	if strings.Contains(output, `"control_refs": null`) {
		t.Error("control_refs should be empty array [], not null")
	}
	if !strings.Contains(output, `"control_refs": []`) {
		t.Error("control_refs should be empty array []")
	}
}
