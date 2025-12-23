// Package policy provides the policy engine and built-in presets
package policy

import (
	"embed"
	"fmt"

	"github.com/mcptrust/mcptrust/internal/models"
	"gopkg.in/yaml.v3"
)

//go:embed presets/*.yaml
var presetFS embed.FS

// presetCache holds loaded presets to avoid re-parsing
var presetCache = map[string]*models.PolicyConfig{}

// presetFiles maps preset names to embedded file paths
var presetFiles = map[string]string{
	"baseline": "presets/baseline.yaml",
	"strict":   "presets/strict.yaml",
}

// GetPreset returns a policy preset by name, or nil if not found
func GetPreset(name string) *models.PolicyConfig {
	// Check cache first
	if cached, ok := presetCache[name]; ok {
		return cached
	}

	// Look up file path
	path, ok := presetFiles[name]
	if !ok {
		return nil
	}

	// Load from embedded FS
	data, err := presetFS.ReadFile(path)
	if err != nil {
		return nil
	}

	var config models.PolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil
	}

	// Cache and return
	presetCache[name] = &config
	return &config
}

// ListPresetNames returns the names of all available presets
func ListPresetNames() []string {
	names := make([]string, 0, len(presetFiles))
	for name := range presetFiles {
		names = append(names, name)
	}
	return names
}

// MustGetPreset returns a preset or panics (for tests)
func MustGetPreset(name string) *models.PolicyConfig {
	p := GetPreset(name)
	if p == nil {
		panic(fmt.Sprintf("preset %q not found", name))
	}
	return p
}
