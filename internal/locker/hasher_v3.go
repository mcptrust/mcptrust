package locker

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/mcptrust/mcptrust/internal/models"
)

// HashNormalizedString sha256
func HashNormalizedString(s string) string {
	normalized := normalizeString(s)
	hash := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("sha256:%x", hash)
}

// normalizeString helper
func normalizeString(s string) string {
	// Normalize line endings: \r\n -> \n, \r -> \n
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	// Trim trailing whitespace per line
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}

// HashJCSJSON sha256
func HashJCSJSON(v interface{}) (string, error) {
	if v == nil {
		return "", nil
	}

	// Safety check: reject floats to avoid JCS edge cases
	if err := rejectFloats(v); err != nil {
		return "", err
	}

	canonical, err := CanonicalizeJSONv2(v)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	hash := sha256.Sum256(canonical)
	return fmt.Sprintf("sha256:%x", hash), nil
}

// rejectFloats check
func rejectFloats(v interface{}) error {
	switch val := v.(type) {
	case float64:
		return fmt.Errorf("float64 values not allowed in lockfile hashing (got %v); use only strings/bools/arrays/objects", val)
	case []interface{}:
		for i, elem := range val {
			if err := rejectFloats(elem); err != nil {
				return fmt.Errorf("in array[%d]: %w", i, err)
			}
		}
	case map[string]interface{}:
		for k, elem := range val {
			if err := rejectFloats(elem); err != nil {
				return fmt.Errorf("in object[%q]: %w", k, err)
			}
		}
	}
	return nil
}

// HashPromptArguments
func HashPromptArguments(args []models.PromptArgument) (string, error) {
	// Convert to []interface{} for canonicalization
	var argsInterface []interface{}
	if len(args) == 0 {
		argsInterface = []interface{}{}
	} else {
		// Sort arguments by name for determinism
		sortedArgs := make([]models.PromptArgument, len(args))
		copy(sortedArgs, args)
		sort.Slice(sortedArgs, func(i, j int) bool {
			return sortedArgs[i].Name < sortedArgs[j].Name
		})

		argsInterface = make([]interface{}, len(sortedArgs))
		for i, arg := range sortedArgs {
			argMap := map[string]interface{}{
				"name": arg.Name,
			}
			if arg.Description != "" {
				argMap["description"] = arg.Description
			}
			if arg.Required {
				argMap["required"] = arg.Required
			}
			argsInterface[i] = argMap
		}
	}

	return HashJCSJSON(argsInterface)
}

// HashTemplate JCS
func HashTemplate(uriTemplate, mimeType string) (string, error) {
	templateMap := map[string]interface{}{
		"uriTemplate": uriTemplate,
	}
	if mimeType != "" {
		templateMap["mimeType"] = mimeType
	}

	return HashJCSJSON(templateMap)
}
