package differ

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/scanner"
	"github.com/wI2L/jsondiff"
)

// DiffType indicates what kind of difference was detected
type DiffType string

const (
	DiffTypeAdded    DiffType = "added"
	DiffTypeRemoved  DiffType = "removed"
	DiffTypeChanged  DiffType = "changed"
	DiffTypeNoChange DiffType = "no_change"
)

// ToolDiff represents the difference for a single tool
type ToolDiff struct {
	ToolName     string
	DiffType     DiffType
	Patches      jsondiff.Patch // Raw JSON patches for schema changes
	Translations []string       // Human-readable translations
}

// DiffResult contains the complete diff result
type DiffResult struct {
	HasChanges bool
	ToolDiffs  []ToolDiff
}

// Engine performs diff operations
type Engine struct {
	lockerManager *locker.Manager
	timeout       time.Duration
}

func NewEngine(timeout time.Duration) *Engine {
	return &Engine{
		lockerManager: locker.NewManager(),
		timeout:       timeout,
	}
}

// ComputeDiff loads the lockfile and compares it against a fresh scan
func (e *Engine) ComputeDiff(ctx context.Context, lockfilePath, command string) (*DiffResult, error) {
	// load lockfile
	if !e.lockerManager.Exists(lockfilePath) {
		return nil, fmt.Errorf("lockfile not found: %s (run 'mcptrust lock' first)", lockfilePath)
	}

	lockfile, err := e.lockerManager.Load(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load lockfile: %w", err)
	}

	// scan
	report, err := scanner.Scan(ctx, command, e.timeout)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	if report.Error != "" {
		return nil, fmt.Errorf("scan error: %s", report.Error)
	}

	// current tools map
	currentTools := make(map[string]models.Tool)
	for _, tool := range report.Tools {
		currentTools[tool.Name] = tool
	}

	result := &DiffResult{
		HasChanges: false,
		ToolDiffs:  []ToolDiff{},
	}

	// removed
	for toolName := range lockfile.Tools {
		if _, found := currentTools[toolName]; !found {
			result.HasChanges = true
			result.ToolDiffs = append(result.ToolDiffs, ToolDiff{
				ToolName:     toolName,
				DiffType:     DiffTypeRemoved,
				Translations: []string{"Tool has been removed from the server."},
			})
		}
	}

	// added/changed
	for _, tool := range report.Tools {
		lockedTool, found := lockfile.Tools[tool.Name]
		if !found {
			// added
			result.HasChanges = true
			result.ToolDiffs = append(result.ToolDiffs, ToolDiff{
				ToolName:     tool.Name,
				DiffType:     DiffTypeAdded,
				Translations: []string{"New tool added to the server."},
			})
			continue
		}

		// schema check
		patches, translations, err := e.compareSchemas(lockedTool, tool)
		if err != nil {
			return nil, fmt.Errorf("failed to compare schemas for tool %s: %w", tool.Name, err)
		}

		// check translations not just patches
		if len(translations) > 0 {
			result.HasChanges = true
			result.ToolDiffs = append(result.ToolDiffs, ToolDiff{
				ToolName:     tool.Name,
				DiffType:     DiffTypeChanged,
				Patches:      patches,
				Translations: translations,
			})
		}
	}

	return result, nil
}

// compareSchemas compares the locked schema hashes against the current tool
func (e *Engine) compareSchemas(locked models.ToolLock, current models.Tool) (jsondiff.Patch, []string, error) {
	// current hashes
	currentDescHash := locker.HashString(current.Description)
	currentSchemaHash, err := locker.HashJSON(current.InputSchema)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash current schema: %w", err)
	}

	var allPatches jsondiff.Patch
	var translations []string

	// desc
	if locked.DescriptionHash != currentDescHash {
		translations = append(translations, "Documentation update: description has changed.")
	}

	// schema diff
	if locked.InputSchemaHash != currentSchemaHash {
		// diff against empty schema since only hash is stored
		patches, err := e.analyzeSchemaChanges(current.InputSchema)
		if err != nil {
			return nil, nil, err
		}

		allPatches = patches
		translations = append(translations, Translate(patches)...)

		// fallback translation
		if len(allPatches) == 0 && locked.InputSchemaHash != currentSchemaHash {
			translations = append(translations, "Input schema has been modified.")
		}
	}

	return allPatches, translations, nil
}

// analyzeSchemaChanges vs empty
func (e *Engine) analyzeSchemaChanges(schema map[string]interface{}) (jsondiff.Patch, error) {
	if schema == nil {
		return nil, nil
	}

	// empty vs current
	emptySchema := map[string]interface{}{}

	sourceJSON, err := json.Marshal(emptySchema)
	if err != nil {
		return nil, err
	}

	targetJSON, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}

	patches, err := jsondiff.CompareJSON(sourceJSON, targetJSON)
	if err != nil {
		return nil, err
	}

	return patches, nil
}

// ComputeFullDiff used for testing
func (e *Engine) ComputeFullDiff(lockedSchema, currentSchema map[string]interface{}) (jsondiff.Patch, error) {
	lockedJSON, err := json.Marshal(lockedSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal locked schema: %w", err)
	}

	currentJSON, err := json.Marshal(currentSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal current schema: %w", err)
	}

	patches, err := jsondiff.CompareJSON(lockedJSON, currentJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to compute diff: %w", err)
	}

	return patches, nil
}
