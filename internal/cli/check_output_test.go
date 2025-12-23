package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mcptrust/mcptrust/internal/differ"
	"github.com/mcptrust/mcptrust/internal/models"
)

func TestParseFailOnLevel(t *testing.T) {
	tests := []struct {
		input     string
		expected  FailOnLevel
		shouldErr bool
	}{
		{"critical", FailOnCritical, false},
		{"CRITICAL", FailOnCritical, false},
		{"moderate", FailOnModerate, false},
		{"Moderate", FailOnModerate, false},
		{"info", FailOnInfo, false},
		{"INFO", FailOnInfo, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseFailOnLevel(tt.input)
			if tt.shouldErr && err == nil {
				t.Errorf("ParseFailOnLevel(%q) expected error, got nil", tt.input)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("ParseFailOnLevel(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.expected {
				t.Errorf("ParseFailOnLevel(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFailOnLevel_ShouldFail(t *testing.T) {
	tests := []struct {
		level    FailOnLevel
		severity differ.SeverityLevel
		expected bool
	}{
		// Critical threshold
		{FailOnCritical, differ.SeverityCritical, true},
		{FailOnCritical, differ.SeverityModerate, false},
		{FailOnCritical, differ.SeveritySafe, false},
		// Moderate threshold
		{FailOnModerate, differ.SeverityCritical, true},
		{FailOnModerate, differ.SeverityModerate, true},
		{FailOnModerate, differ.SeveritySafe, false},
		// Info threshold (all fail)
		{FailOnInfo, differ.SeverityCritical, true},
		{FailOnInfo, differ.SeverityModerate, true},
		{FailOnInfo, differ.SeveritySafe, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.level)+"_"+severityName(tt.severity), func(t *testing.T) {
			got := tt.level.ShouldFail(tt.severity)
			if got != tt.expected {
				t.Errorf("FailOnLevel(%q).ShouldFail(%d) = %v, want %v", tt.level, tt.severity, got, tt.expected)
			}
		})
	}
}

func severityName(s differ.SeverityLevel) string {
	switch s {
	case differ.SeverityCritical:
		return "critical"
	case differ.SeverityModerate:
		return "moderate"
	default:
		return "safe"
	}
}

func TestBuildCheckResult(t *testing.T) {
	drift := &differ.V3Result{
		HasDrift: true,
		Drifts: []differ.V3DriftItem{
			{Type: "PROMPT_ADDED", Severity: differ.SeverityCritical, Identifier: "prompt1"},
			{Type: "PROMPT_DESC_CHANGED", Severity: differ.SeverityModerate, Identifier: "prompt2"},
		},
	}

	t.Run("fail on critical with critical drift", func(t *testing.T) {
		result := BuildCheckResult("3.0", "test-server", "mcp-lock.json", drift, nil, "", FailOnCritical)
		if result.Outcome != "FAIL" {
			t.Errorf("Outcome = %s, want FAIL", result.Outcome)
		}
		if result.Summary.Critical != 1 {
			t.Errorf("Summary.Critical = %d, want 1", result.Summary.Critical)
		}
		if result.Summary.Moderate != 1 {
			t.Errorf("Summary.Moderate = %d, want 1", result.Summary.Moderate)
		}
	})

	t.Run("no drift passes", func(t *testing.T) {
		noDrift := &differ.V3Result{HasDrift: false}
		result := BuildCheckResult("3.0", "test-server", "mcp-lock.json", noDrift, nil, "", FailOnCritical)
		if result.Outcome != "PASS" {
			t.Errorf("Outcome = %s, want PASS", result.Outcome)
		}
	})

	t.Run("policy deny overrides drift pass", func(t *testing.T) {
		noDrift := &differ.V3Result{HasDrift: false}
		policyResults := []models.PolicyResult{
			{RuleName: "test_rule", Passed: false, FailureMsg: "test failure", Severity: models.PolicySeverityError},
		}
		result := BuildCheckResult("3.0", "test-server", "mcp-lock.json", noDrift, policyResults, "strict", FailOnCritical)
		if result.Outcome != "FAIL" {
			t.Errorf("Outcome = %s, want FAIL", result.Outcome)
		}
		if result.Policy == nil || result.Policy.Passed {
			t.Error("Policy should be denied")
		}
	})
}

func TestFormatJSONOutput(t *testing.T) {
	result := &CheckResult{
		LockfileVersion: "3.0",
		Server:          "test-server",
		LockfilePath:    "mcp-lock.json",
		Summary:         CheckSummary{Critical: 1, Total: 1},
		Drift: []DriftOutputItem{
			{Type: "PROMPT_ADDED", Severity: "critical", Identifier: "test"},
		},
		FailOn:  "critical",
		Outcome: "FAIL",
	}

	output, err := FormatJSONOutput(result)
	if err != nil {
		t.Fatalf("FormatJSONOutput error: %v", err)
	}

	// Verify it's valid JSON
	var parsed CheckResult
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if parsed.Outcome != "FAIL" {
		t.Errorf("Parsed Outcome = %s, want FAIL", parsed.Outcome)
	}
}

func TestFormatTextOutput(t *testing.T) {
	result := &CheckResult{
		LockfileVersion: "3.0",
		Server:          "test-server",
		LockfilePath:    "mcp-lock.json",
		Summary:         CheckSummary{Critical: 1, Moderate: 1, Total: 2},
		Drift: []DriftOutputItem{
			{Type: "PROMPT_ADDED", Severity: "critical", Identifier: "new_prompt"},
			{Type: "PROMPT_DESC_CHANGED", Severity: "moderate", Identifier: "old_prompt"},
		},
		FailOn:  "critical",
		Outcome: "FAIL",
	}

	output := FormatTextOutput(result)

	// Verify key elements are present
	if !strings.Contains(output, "FAIL") {
		t.Error("Output should contain FAIL")
	}
	if !strings.Contains(output, "test-server") {
		t.Error("Output should contain server name")
	}
	if !strings.Contains(output, "CRITICAL (1)") {
		t.Error("Output should contain CRITICAL count")
	}
	if !strings.Contains(output, "MODERATE (1)") {
		t.Error("Output should contain MODERATE count")
	}
	if !strings.Contains(output, "PROMPT_ADDED") {
		t.Error("Output should contain drift type")
	}
}
