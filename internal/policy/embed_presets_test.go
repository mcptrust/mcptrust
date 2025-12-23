package policy

import (
	"testing"
)

// TestEmbeddedPresetFilesExist verifies that the //go:embed directive is correctly
// configured and the preset YAML files are actually embedded in the binary.
// This test will fail if:
// - The embed directive syntax is broken (e.g., missing space after //go:embed)
// - The preset file paths change without updating the embed directive
// - The preset files are deleted
func TestEmbeddedPresetFilesExist(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"baseline", "presets/baseline.yaml"},
		{"strict", "presets/strict.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := presetFS.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("failed to read embedded file %q: %v (check //go:embed directive)", tt.path, err)
			}
			if len(data) == 0 {
				t.Errorf("embedded file %q is empty", tt.path)
			}
			// Sanity check: should contain YAML-like content
			if len(data) < 10 {
				t.Errorf("embedded file %q suspiciously small (%d bytes)", tt.path, len(data))
			}
		})
	}
}

// TestGetPreset_BaselineAndStrict verifies that GetPreset returns valid, non-empty
// policy configurations for the built-in presets.
// This test catches regressions where:
// - Embed is broken (presetFS empty)
// - YAML parsing fails silently
// - Policy structure changes incompatibly
func TestGetPreset_BaselineAndStrict(t *testing.T) {
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
				t.Fatalf("GetPreset(%q) returned nil (check embed directive and YAML parsing)", tt.name)
			}
			if preset.Name == "" {
				t.Errorf("preset %q has empty Name field", tt.name)
			}
			if len(preset.Rules) == 0 {
				t.Errorf("preset %q has no rules", tt.name)
			}
		})
	}
}
