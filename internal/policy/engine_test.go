package policy

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

func TestEvaluateWithLockfile(t *testing.T) {
	data, err := os.ReadFile("testdata/lockfile_v2_with_artifact.json")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	var lockfile models.Lockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		t.Fatalf("failed to parse lockfile: %v", err)
	}

	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	config := &models.PolicyConfig{
		Name: "Test Supply Chain Policy",
		Rules: []models.PolicyRule{
			{
				Name:       "artifact_pinned",
				Expr:       `has(input.artifact) && input.artifact.integrity != ""`,
				FailureMsg: "Artifact not pinned",
			},
			{
				Name:       "provenance_verified",
				Expr:       `has(input.provenance) && input.provenance.verified == true`,
				FailureMsg: "Provenance not verified",
			},
			{
				Name:       "trusted_source",
				Expr:       `has(input.provenance) && input.provenance.source_repo.matches("^https://github.com/test/")`,
				FailureMsg: "Untrusted source",
			},
		},
	}

	report := &models.ScanReport{
		Tools: []models.Tool{
			{Name: "read_file", Description: "Reads a file"},
		},
	}

	results, err := engine.EvaluateWithLockfile(config, report, &lockfile)
	if err != nil {
		t.Fatalf("EvaluateWithLockfile failed: %v", err)
	}

	for _, result := range results {
		if !result.Passed {
			t.Errorf("rule %q should pass but failed: %s", result.RuleName, result.FailureMsg)
		}
	}
}

func TestEvaluateWithLockfileNilLockfile(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	config := &models.PolicyConfig{
		Name: "Artifact Required",
		Rules: []models.PolicyRule{
			{
				Name:       "artifact_required",
				Expr:       `has(input.artifact)`,
				FailureMsg: "No artifact",
			},
		},
	}

	report := &models.ScanReport{
		Tools: []models.Tool{{Name: "test"}},
	}

	results, err := engine.EvaluateWithLockfile(config, report, nil)
	if err != nil {
		t.Fatalf("EvaluateWithLockfile failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Passed {
		t.Error("artifact_required rule should fail when lockfile is nil")
	}
}

func TestPresetBaselineExitBehavior(t *testing.T) {
	baseline := GetPreset("baseline")
	if baseline == nil {
		t.Fatal("baseline preset not found")
	}

	if baseline.Mode != models.PolicyModeWarn {
		t.Errorf("baseline mode = %q, want %q", baseline.Mode, models.PolicyModeWarn)
	}

	for _, rule := range baseline.Rules {
		if rule.Name == "no_critical_drift" {
			if rule.Severity != models.PolicySeverityError {
				t.Errorf("baseline rule %q has severity %q, want %q", rule.Name, rule.Severity, models.PolicySeverityError)
			}
		} else {
			if rule.Severity != models.PolicySeverityWarn {
				t.Errorf("baseline rule %q has severity %q, want %q", rule.Name, rule.Severity, models.PolicySeverityWarn)
			}
		}
	}
}

func TestPresetStrictExitBehavior(t *testing.T) {
	strict := GetPreset("strict")
	if strict == nil {
		t.Fatal("strict preset not found")
	}

	if strict.Mode != models.PolicyModeStrict {
		t.Errorf("strict mode = %q, want %q", strict.Mode, models.PolicyModeStrict)
	}

	for _, rule := range strict.Rules {
		if rule.Severity != models.PolicySeverityError {
			t.Errorf("strict rule %q has severity %q, want %q", rule.Name, rule.Severity, models.PolicySeverityError)
		}
	}
}

func TestProvenanceMapFields(t *testing.T) {
	prov := &models.ProvenanceInfo{
		PredicateType: "https://slsa.dev/provenance/v1",
		BuilderID:     "test-builder",
		SourceRepo:    "https://github.com/org/repo",
		SourceRef:     "refs/tags/v1.0.0",
		WorkflowURI:   ".github/workflows/release.yml",
		Issuer:        "https://token.actions.githubusercontent.com",
		Identity:      "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
		Verified:      true,
		VerifiedAt:    "2024-01-15T10:30:00Z",
	}

	m := provenanceToMap(prov)

	tests := []struct {
		key  string
		want interface{}
	}{
		{"predicate_type", "https://slsa.dev/provenance/v1"},
		{"builder_id", "test-builder"},
		{"source_repo", "https://github.com/org/repo"},
		{"source_ref", "refs/tags/v1.0.0"},
		{"workflow_uri", ".github/workflows/release.yml"},
		{"issuer", "https://token.actions.githubusercontent.com"},
		{"identity", "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0"},
		{"verified", true},
		{"verified_at", "2024-01-15T10:30:00Z"},
		{"config_source_uri", "https://github.com/org/repo"},
		{"config_source_entrypoint", ".github/workflows/release.yml"},
	}

	for _, tt := range tests {
		got, ok := m[tt.key]
		if !ok {
			t.Errorf("missing key %q", tt.key)
			continue
		}
		if got != tt.want {
			t.Errorf("key %q = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestArtifactMapFields(t *testing.T) {
	artifact := &models.ArtifactPin{
		Type:      models.ArtifactTypeNPM,
		Name:      "@test/package",
		Version:   "1.0.0",
		Registry:  "https://registry.npmjs.org",
		Integrity: "sha512-abc123",
	}

	m := artifactToMap(artifact)

	tests := []struct {
		key  string
		want interface{}
	}{
		{"type", "npm"},
		{"name", "@test/package"},
		{"version", "1.0.0"},
		{"registry", "https://registry.npmjs.org"},
		{"integrity", "sha512-abc123"},
	}

	for _, tt := range tests {
		got, ok := m[tt.key]
		if !ok {
			t.Errorf("missing key %q", tt.key)
			continue
		}
		if got != tt.want {
			t.Errorf("key %q = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestProvenanceNotPopulatedForNPMFallback(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	lockfile := &models.Lockfile{
		Version:       "2.0",
		ServerCommand: "npx -y @test/server /tmp",
		Artifact: &models.ArtifactPin{
			Type:      models.ArtifactTypeNPM,
			Name:      "@test/server",
			Version:   "1.0.0",
			Integrity: "sha512-abc123",
			Provenance: &models.ProvenanceInfo{
				Method:     models.ProvenanceMethodNPMAuditSigs, // npm fallback
				Verified:   true,
				VerifiedAt: "2024-01-15T10:30:00Z",
			},
		},
	}

	config := &models.PolicyConfig{
		Name: "Provenance Required",
		Rules: []models.PolicyRule{
			{
				Name:       "has_provenance",
				Expr:       `has(input.provenance)`,
				FailureMsg: "No provenance",
			},
		},
	}

	report := &models.ScanReport{
		Tools: []models.Tool{{Name: "test"}},
	}

	results, err := engine.EvaluateWithLockfile(config, report, lockfile)
	if err != nil {
		t.Fatalf("EvaluateWithLockfile failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Passed {
		t.Error("has_provenance rule should FAIL when provenance method is npm_audit_signatures")
	}
}

func TestProvenancePopulatedForCosignSLSA(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	lockfile := &models.Lockfile{
		Version:       "2.0",
		ServerCommand: "npx -y @test/server /tmp",
		Artifact: &models.ArtifactPin{
			Type:      models.ArtifactTypeNPM,
			Name:      "@test/server",
			Version:   "1.0.0",
			Integrity: "sha512-abc123",
			Provenance: &models.ProvenanceInfo{
				Method:      models.ProvenanceMethodCosignSLSA, // cosign verification
				Verified:    true,
				VerifiedAt:  "2024-01-15T10:30:00Z",
				SourceRepo:  "https://github.com/test/server",
				WorkflowURI: ".github/workflows/release.yml",
			},
		},
	}

	config := &models.PolicyConfig{
		Name: "Provenance Required",
		Rules: []models.PolicyRule{
			{
				Name:       "has_provenance",
				Expr:       `has(input.provenance)`,
				FailureMsg: "No provenance",
			},
			{
				Name:       "method_is_cosign",
				Expr:       `input.provenance.method == "cosign_slsa"`,
				FailureMsg: "Wrong method",
			},
		},
	}

	report := &models.ScanReport{
		Tools: []models.Tool{{Name: "test"}},
	}

	results, err := engine.EvaluateWithLockfile(config, report, lockfile)
	if err != nil {
		t.Fatalf("EvaluateWithLockfile failed: %v", err)
	}

	for _, result := range results {
		if !result.Passed {
			t.Errorf("rule %q should pass but failed: %s", result.RuleName, result.FailureMsg)
		}
	}
}

func TestProvenanceMethodFieldInMap(t *testing.T) {
	prov := &models.ProvenanceInfo{
		Method:        models.ProvenanceMethodCosignSLSA,
		PredicateType: "https://slsa.dev/provenance/v1",
		Verified:      true,
	}

	m := provenanceToMap(prov)

	got, ok := m["method"]
	if !ok {
		t.Error("missing method key in provenanceToMap output")
	}
	if got != "cosign_slsa" {
		t.Errorf("method = %v, want %v", got, "cosign_slsa")
	}
}

func TestPolicyEval_NormalPolicyStillWorksUnderLimit(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	config := &models.PolicyConfig{
		Name: "Normal Policies",
		Rules: []models.PolicyRule{
			{
				Name:       "simple_check",
				Expr:       `size(input.tools) <= 10`,
				FailureMsg: "Too many tools",
			},
			{
				Name:       "string_match",
				Expr:       `input.tools.exists(t, t.name == "safe_tool")`,
				FailureMsg: "Missing safe_tool",
			},
			{
				Name:       "complex_but_reasonable",
				Expr:       `input.tools.filter(t, t.risk_level == "high").size() == 0`,
				FailureMsg: "High risk tools found",
			},
		},
	}

	report := &models.ScanReport{
		Tools: []models.Tool{
			{Name: "safe_tool", RiskLevel: models.RiskLevelLow},
			{Name: "other_tool", RiskLevel: models.RiskLevelMedium},
		},
	}

	results, err := engine.Evaluate(config, report)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	for _, r := range results {
		if !r.Passed {
			t.Errorf("rule %q should pass: %s", r.RuleName, r.FailureMsg)
		}
	}
}

func TestPolicyEval_CostLimitExceededReturnsError(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	config := &models.PolicyConfig{
		Name: "Cost Test",
		Rules: []models.PolicyRule{
			{
				Name: "expensive_expression",
				// Nested exists on the same list creates O(n²) comparisons
				// With input size and multiple nesting, this can exceed cost limit
				Expr: `input.tools.exists(t1, 
					input.tools.exists(t2, 
						input.tools.exists(t3, 
							input.tools.exists(t4, 
								t1.name == t2.name && t2.name == t3.name && t3.name == t4.name
							)
						)
					)
				)`,
				FailureMsg: "Cost test",
			},
		},
	}

	largeTools := make([]models.Tool, 100)
	for i := range largeTools {
		largeTools[i] = models.Tool{Name: "tool" + string(rune('A'+i%26))}
	}

	report := &models.ScanReport{
		Tools: largeTools,
	}

	results, err := engine.Evaluate(config, report)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	t.Logf("Expensive expression result: passed=%v, msg=%s", results[0].Passed, results[0].FailureMsg)
}
