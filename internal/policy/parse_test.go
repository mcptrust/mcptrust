package policy

import (
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
	"gopkg.in/yaml.v3"
)

func TestParsePolicy_NoMetadata(t *testing.T) {
	// YAML without the new metadata fields should still parse correctly
	yamlContent := `
name: "Test Policy"
rules:
  - name: "test_rule"
    expr: 'size(input.tools) > 0'
    failure_msg: "No tools found"
    severity: error
`

	var config models.PolicyConfig
	if err := yaml.Unmarshal([]byte(yamlContent), &config); err != nil {
		t.Fatalf("failed to parse YAML without metadata: %v", err)
	}

	if config.Name != "Test Policy" {
		t.Errorf("name = %q, want %q", config.Name, "Test Policy")
	}

	if len(config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(config.Rules))
	}

	rule := config.Rules[0]
	if rule.Name != "test_rule" {
		t.Errorf("rule name = %q, want %q", rule.Name, "test_rule")
	}

	// New metadata fields should be nil/empty
	if rule.ControlRefs != nil {
		t.Errorf("ControlRefs should be nil, got %v", rule.ControlRefs)
	}
	if rule.Evidence != nil {
		t.Errorf("Evidence should be nil, got %v", rule.Evidence)
	}
	if rule.EvidenceCommands != nil {
		t.Errorf("EvidenceCommands should be nil, got %v", rule.EvidenceCommands)
	}
}

func TestParsePolicy_WithMetadata(t *testing.T) {
	// YAML with all metadata fields should parse correctly
	yamlContent := `
name: "Test Policy with Metadata"
rules:
  - name: "test_rule"
    expr: 'size(input.tools) > 0'
    failure_msg: "No tools found"
    severity: warn
    control_refs:
      - "NIST AI RMF: GOVERN 1.1"
      - "SOC2: CC7.2"
    evidence:
      - "Signed mcp-lock.json with integrity hash"
    evidence_commands:
      - "mcptrust verify --lockfile mcp-lock.json"
      - "mcptrust artifact verify --deep mcp-lock.json"
`

	var config models.PolicyConfig
	if err := yaml.Unmarshal([]byte(yamlContent), &config); err != nil {
		t.Fatalf("failed to parse YAML with metadata: %v", err)
	}

	if len(config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(config.Rules))
	}

	rule := config.Rules[0]

	// Check control_refs
	if len(rule.ControlRefs) != 2 {
		t.Errorf("expected 2 ControlRefs, got %d", len(rule.ControlRefs))
	}
	if rule.ControlRefs[0] != "NIST AI RMF: GOVERN 1.1" {
		t.Errorf("ControlRefs[0] = %q, want %q", rule.ControlRefs[0], "NIST AI RMF: GOVERN 1.1")
	}

	// Check evidence
	if len(rule.Evidence) != 1 {
		t.Errorf("expected 1 Evidence entry, got %d", len(rule.Evidence))
	}

	// Check evidence_commands
	if len(rule.EvidenceCommands) != 2 {
		t.Errorf("expected 2 EvidenceCommands, got %d", len(rule.EvidenceCommands))
	}
}

func TestParsePolicy_MixedRules(t *testing.T) {
	// Some rules with metadata, some without
	yamlContent := `
name: "Mixed Policy"
rules:
  - name: "rule_with_metadata"
    expr: 'true'
    failure_msg: "Always passes"
    control_refs:
      - "NIST AI RMF: MAP 1.1"
  - name: "rule_without_metadata"
    expr: 'true'
    failure_msg: "Also passes"
`

	var config models.PolicyConfig
	if err := yaml.Unmarshal([]byte(yamlContent), &config); err != nil {
		t.Fatalf("failed to parse mixed YAML: %v", err)
	}

	if len(config.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(config.Rules))
	}

	// First rule has metadata
	if len(config.Rules[0].ControlRefs) != 1 {
		t.Errorf("first rule should have 1 control ref")
	}

	// Second rule has no metadata
	if config.Rules[1].ControlRefs != nil {
		t.Errorf("second rule should have nil ControlRefs")
	}
}

func TestPresetMetadataPresent(t *testing.T) {
	// Verify that embedded presets have metadata populated
	tests := []struct {
		name string
	}{
		{"baseline"},
		{"strict"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preset := GetPreset(tt.name)
			if preset == nil {
				t.Fatalf("preset %q not found", tt.name)
			}

			if len(preset.Rules) == 0 {
				t.Fatal("preset has no rules")
			}

			// At least one rule should have control_refs
			hasControlRefs := false
			for _, rule := range preset.Rules {
				if len(rule.ControlRefs) > 0 {
					hasControlRefs = true
					break
				}
			}
			if !hasControlRefs {
				t.Errorf("preset %q should have at least one rule with control_refs", tt.name)
			}
		})
	}
}

func TestMetadataDoesNotAffectEnforcement(t *testing.T) {
	// Regression test: same rule with/without metadata yields identical pass/fail
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Rule without metadata
	ruleWithout := models.PolicyRule{
		Name:       "test_rule",
		Expr:       `size(input.tools) > 0`,
		FailureMsg: "No tools",
		Severity:   models.PolicySeverityError,
	}

	// Same rule WITH metadata (should not change pass/fail behavior)
	ruleWith := models.PolicyRule{
		Name:       "test_rule",
		Expr:       `size(input.tools) > 0`,
		FailureMsg: "No tools",
		Severity:   models.PolicySeverityError,
		ControlRefs: []string{
			"NIST AI RMF: GOVERN 1.1",
			"SOC2: CC7.2",
		},
		Evidence: []string{
			"Signed mcp-lock.json",
		},
		EvidenceCommands: []string{
			"mcptrust verify --lockfile mcp-lock.json",
		},
	}

	configWithout := &models.PolicyConfig{
		Name:  "Without Metadata",
		Rules: []models.PolicyRule{ruleWithout},
	}
	configWith := &models.PolicyConfig{
		Name:  "With Metadata",
		Rules: []models.PolicyRule{ruleWith},
	}

	// Test with tools (should pass)
	reportPass := &models.ScanReport{
		Tools: []models.Tool{{Name: "test_tool"}},
	}

	resultsWithout, err := engine.Evaluate(configWithout, reportPass)
	if err != nil {
		t.Fatalf("evaluate without metadata failed: %v", err)
	}
	resultsWith, err := engine.Evaluate(configWith, reportPass)
	if err != nil {
		t.Fatalf("evaluate with metadata failed: %v", err)
	}

	if resultsWithout[0].Passed != resultsWith[0].Passed {
		t.Errorf("metadata changed pass/fail: without=%v, with=%v",
			resultsWithout[0].Passed, resultsWith[0].Passed)
	}

	// Test without tools (should fail)
	reportFail := &models.ScanReport{
		Tools: []models.Tool{},
	}

	resultsWithoutFail, _ := engine.Evaluate(configWithout, reportFail)
	resultsWithFail, _ := engine.Evaluate(configWith, reportFail)

	if resultsWithoutFail[0].Passed != resultsWithFail[0].Passed {
		t.Errorf("metadata changed pass/fail on failure: without=%v, with=%v",
			resultsWithoutFail[0].Passed, resultsWithFail[0].Passed)
	}

	// Both should fail
	if resultsWithFail[0].Passed {
		t.Error("expected rule to fail with empty tools")
	}
}
