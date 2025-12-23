package locker

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

func TestLoadLockfileBackwardCompatMissingMethod(t *testing.T) {
	// Test that loading a lockfile with provenance but missing method
	// defaults to "unverified" for backward compatibility

	manager := NewManager()

	lockfile, err := manager.Load("testdata/lockfile_v2_missing_method.json")
	if err != nil {
		t.Fatalf("failed to load lockfile: %v", err)
	}

	if lockfile.Artifact == nil {
		t.Fatal("expected artifact to be present")
	}
	if lockfile.Artifact.Provenance == nil {
		t.Fatal("expected provenance to be present")
	}

	// The missing method should default to "unverified"
	if lockfile.Artifact.Provenance.Method != models.ProvenanceMethodUnverified {
		t.Errorf("expected method to be %q, got %q",
			models.ProvenanceMethodUnverified,
			lockfile.Artifact.Provenance.Method)
	}

	// Other fields should still be populated
	if lockfile.Artifact.Provenance.Verified != true {
		t.Error("expected verified to be true")
	}
	if lockfile.Artifact.Provenance.SourceRepo != "https://github.com/test/server" {
		t.Errorf("expected source_repo to be populated, got %q", lockfile.Artifact.Provenance.SourceRepo)
	}
}

func TestLoadLockfileWithExistingMethod(t *testing.T) {
	// Test that loading a lockfile with an existing method preserves it

	// Create a temp lockfile with method set
	lockfile := &models.Lockfile{
		Version:       "2.0",
		ServerCommand: "test",
		Artifact: &models.ArtifactPin{
			Type:      models.ArtifactTypeNPM,
			Name:      "@test/pkg",
			Version:   "1.0.0",
			Integrity: "sha512-abc",
			Provenance: &models.ProvenanceInfo{
				Method:   models.ProvenanceMethodCosignSLSA,
				Verified: true,
			},
		},
	}

	// Write to temp file
	data, err := json.MarshalIndent(lockfile, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "lockfile-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	tmpFile.Close()

	// Load it back
	manager := NewManager()
	loaded, err := manager.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	// Method should be preserved as cosign_slsa
	if loaded.Artifact.Provenance.Method != models.ProvenanceMethodCosignSLSA {
		t.Errorf("expected method to be preserved as %q, got %q",
			models.ProvenanceMethodCosignSLSA,
			loaded.Artifact.Provenance.Method)
	}
}
