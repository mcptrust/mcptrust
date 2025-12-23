package artifact

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

func TestParseInTotoStatementV1(t *testing.T) {
	// SLSA v1 format statement
	statementJSON := `{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [
			{
				"name": "pkg:npm/@scope/package@1.0.0",
				"digest": {"sha512": "abc123"}
			}
		],
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {
			"buildDefinition": {
				"buildType": "https://actions.github.io/buildtypes/workflow/v1",
				"externalParameters": {
					"repository": "https://github.com/org/repo",
					"ref": "refs/tags/v1.0.0",
					"workflow": {
						"path": ".github/workflows/release.yml"
					}
				}
			},
			"runDetails": {
				"builder": {
					"id": "https://github.com/actions/runner"
				},
				"metadata": {
					"invocationId": "https://github.com/org/repo/actions/runs/12345"
				}
			}
		}
	}`

	info, raw, err := parseInTotoStatement([]byte(statementJSON), "")
	if err != nil {
		t.Fatalf("parseInTotoStatement failed: %v", err)
	}

	if info.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("PredicateType = %q, want %q", info.PredicateType, "https://slsa.dev/provenance/v1")
	}
	if info.BuilderID != "https://github.com/actions/runner" {
		t.Errorf("BuilderID = %q, want %q", info.BuilderID, "https://github.com/actions/runner")
	}
	if info.SourceRepo != "https://github.com/org/repo" {
		t.Errorf("SourceRepo = %q, want %q", info.SourceRepo, "https://github.com/org/repo")
	}
	if info.SourceRef != "refs/tags/v1.0.0" {
		t.Errorf("SourceRef = %q, want %q", info.SourceRef, "refs/tags/v1.0.0")
	}
	if info.WorkflowURI != ".github/workflows/release.yml" {
		t.Errorf("WorkflowURI = %q, want %q", info.WorkflowURI, ".github/workflows/release.yml")
	}

	if raw == nil {
		t.Error("raw statement should not be nil")
	}
}

func TestParseInTotoStatementOlder(t *testing.T) {
	// Older SLSA generator format
	statementJSON := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [
			{
				"name": "pkg:npm/@scope/package@1.0.0",
				"digest": {"sha512": "abc123"}
			}
		],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"builder": {
				"id": "https://github.com/npm/cli"
			},
			"invocation": {
				"configSource": {
					"uri": "git+https://github.com/org/repo@refs/heads/main",
					"digest": {"sha1": "abc123def456"},
					"entryPoint": ".github/workflows/publish.yml"
				}
			},
			"materials": [
				{
					"uri": "git+https://github.com/org/repo",
					"digest": {"sha1": "abc123def456"}
				}
			]
		}
	}`

	info, raw, err := parseInTotoStatement([]byte(statementJSON), "")
	if err != nil {
		t.Fatalf("parseInTotoStatement failed: %v", err)
	}

	if info.BuilderID != "https://github.com/npm/cli" {
		t.Errorf("BuilderID = %q, want %q", info.BuilderID, "https://github.com/npm/cli")
	}
	if info.SourceRepo != "git+https://github.com/org/repo@refs/heads/main" {
		t.Errorf("SourceRepo = %q, want %q", info.SourceRepo, "git+https://github.com/org/repo@refs/heads/main")
	}
	if info.WorkflowURI != ".github/workflows/publish.yml" {
		t.Errorf("WorkflowURI = %q, want %q", info.WorkflowURI, ".github/workflows/publish.yml")
	}

	if raw == nil {
		t.Error("raw statement should not be nil")
	}
}

func TestParseInTotoStatementExpectedSource(t *testing.T) {
	statementJSON := `{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [{"name": "pkg", "digest": {"sha512": "abc"}}],
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {
			"buildDefinition": {
				"externalParameters": {
					"repository": "https://github.com/other-org/repo"
				}
			},
			"runDetails": {"builder": {"id": "builder"}}
		}
	}`

	// Should fail when expected source doesn't match
	_, _, err := parseInTotoStatement([]byte(statementJSON), "^https://github.com/my-org/")
	if err == nil {
		t.Error("expected error when source doesn't match pattern")
	}

	// Should succeed when expected source matches
	_, _, err = parseInTotoStatement([]byte(statementJSON), "https://github.com/other-org")
	if err != nil {
		t.Errorf("unexpected error when source matches: %v", err)
	}
}

func TestParseInTotoStatementNotProvenance(t *testing.T) {
	statementJSON := `{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [{"name": "pkg", "digest": {"sha512": "abc"}}],
		"predicateType": "https://example.com/other-type/v1",
		"predicate": {}
	}`

	_, _, err := parseInTotoStatement([]byte(statementJSON), "")
	if err == nil {
		t.Error("expected error for non-provenance predicate type")
	}
}

func TestParseDSSEEnvelope(t *testing.T) {
	// Create a valid DSSE envelope with base64 encoded payload
	statement := `{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"runDetails":{"builder":{"id":"test"}}}}`
	envelope := DSSEEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbXSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2xzYS5kZXYvcHJvdmVuYW5jZS92MSIsInByZWRpY2F0ZSI6eyJydW5EZXRhaWxzIjp7ImJ1aWxkZXIiOnsiaWQiOiJ0ZXN0In19fX0=",
		Signatures:  []DSSESig{{KeyID: "key1", Sig: "sig1"}},
	}

	envelopeJSON, _ := json.Marshal(envelope)

	info, _, err := parseNPMAttestationBundle(envelopeJSON, "")
	if err != nil {
		t.Fatalf("parseNPMAttestationBundle failed: %v", err)
	}

	if info.BuilderID != "test" {
		t.Errorf("BuilderID = %q, want %q", info.BuilderID, "test")
	}

	// For statement verification
	_ = statement
}

func TestGetWorkflowPath(t *testing.T) {
	tests := []struct {
		identity string
		want     string
	}{
		{
			identity: "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			want:     ".github/workflows/release.yml",
		},
		{
			identity: "https://github.com/org/repo/.github/workflows/ci.yaml@refs/heads/main",
			want:     ".github/workflows/ci.yaml",
		},
		{
			identity: "no-workflow-path",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.identity, func(t *testing.T) {
			got := GetWorkflowPath(tt.identity)
			if got != tt.want {
				t.Errorf("GetWorkflowPath(%q) = %q, want %q", tt.identity, got, tt.want)
			}
		})
	}
}

func TestIsCosignAvailable(t *testing.T) {
	// This test just verifies the function doesn't panic
	// Actual availability depends on the test environment
	ctx := context.Background()
	_ = isCosignAvailable(ctx)
}

func TestIsNPMAvailable(t *testing.T) {
	// This test just verifies the function doesn't panic
	// Actual availability depends on the test environment
	ctx := context.Background()
	_ = isNPMAvailable(ctx)
}

func TestParseInTotoStatementSetsMethod(t *testing.T) {
	// parseInTotoStatement returns ProvenanceInfo without Method set
	// (Method is set by the caller after verification)
	// This test verifies the parsed info structure is correct

	statementJSON := `{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [{"name": "pkg", "digest": {"sha512": "abc"}}],
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {
			"buildDefinition": {
				"externalParameters": {
					"repository": "https://github.com/org/repo"
				}
			},
			"runDetails": {"builder": {"id": "https://github.com/actions/runner"}}
		}
	}`

	info, _, err := parseInTotoStatement([]byte(statementJSON), "")
	if err != nil {
		t.Fatalf("parseInTotoStatement failed: %v", err)
	}

	// After parsing, Method should be empty (caller sets it)
	if info.Method != "" {
		t.Errorf("Method should be empty after parsing, got %q", info.Method)
	}

	// But all other fields should be populated
	if info.SourceRepo != "https://github.com/org/repo" {
		t.Errorf("SourceRepo = %q, want %q", info.SourceRepo, "https://github.com/org/repo")
	}
	if info.BuilderID != "https://github.com/actions/runner" {
		t.Errorf("BuilderID = %q, want %q", info.BuilderID, "https://github.com/actions/runner")
	}
}

func TestProvenanceMethodConstants(t *testing.T) {
	// Verify the constants are correctly defined
	tests := []struct {
		method models.ProvenanceMethod
		want   string
	}{
		{models.ProvenanceMethodCosignSLSA, "cosign_slsa"},
		{models.ProvenanceMethodNPMAuditSigs, "npm_audit_signatures"},
		{models.ProvenanceMethodUnverified, "unverified"},
	}

	for _, tt := range tests {
		if string(tt.method) != tt.want {
			t.Errorf("ProvenanceMethod constant %q != %q", tt.method, tt.want)
		}
	}
}
