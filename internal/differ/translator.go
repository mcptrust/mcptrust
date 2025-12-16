package differ

import (
	"strings"

	"github.com/wI2L/jsondiff"
)

// Translate patches to english
func Translate(patches jsondiff.Patch) []string {
	if len(patches) == 0 {
		return nil
	}

	var translations []string
	seen := make(map[string]bool)

	for _, op := range patches {
		translation := translateOperation(op)
		if translation != "" && !seen[translation] {
			seen[translation] = true
			translations = append(translations, translation)
		}
	}

	return translations
}

func translateOperation(op jsondiff.Operation) string {
	path := op.Path
	opType := op.Type

	switch opType {
	case jsondiff.OperationAdd:
		return translateAdd(path)
	case jsondiff.OperationRemove:
		return translateRemove(path)
	case jsondiff.OperationReplace:
		return translateReplace(path)
	default:
		return ""
	}
}

// translateAdd
func translateAdd(path string) string {
	pathLower := strings.ToLower(path)

	// required arg added
	if strings.HasSuffix(pathLower, "/required") || strings.Contains(pathLower, "/required/") {
		return "⚠️  CRITICAL: New required argument added."
	}

	// property added
	if strings.Contains(pathLower, "/properties/") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if part == "properties" && i+1 < len(parts) {
				propName := parts[i+1]
				return "New argument '" + propName + "' added."
			}
		}
		return "New argument added."
	}

	// Generic add
	return "New capability/argument added."
}

// translateRemove
func translateRemove(path string) string {
	pathLower := strings.ToLower(path)

	// required removed
	if strings.HasSuffix(pathLower, "/required") || strings.Contains(pathLower, "/required/") {
		return "Required argument constraint removed."
	}

	// property removed
	if strings.Contains(pathLower, "/properties/") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if part == "properties" && i+1 < len(parts) {
				propName := parts[i+1]
				return "Argument '" + propName + "' removed."
			}
		}
		return "Argument removed."
	}

	return "Capability removed."
}

// translateReplace
func translateReplace(path string) string {
	pathLower := strings.ToLower(path)

	// desc
	if strings.Contains(pathLower, "description") {
		return "Documentation update."
	}

	// type
	if strings.HasSuffix(pathLower, "/type") {
		return "Argument type changed."
	}

	// required
	if strings.Contains(pathLower, "/required") {
		return "⚠️  CRITICAL: Required arguments modified."
	}

	return "Capability modified."
}

// SeverityLevel 0=safe, 1=mod, 2=crit
type SeverityLevel int

const (
	SeveritySafe SeverityLevel = iota
	SeverityModerate
	SeverityCritical
)

// GetSeverity
func GetSeverity(translation string) SeverityLevel {
	lowerMsg := strings.ToLower(translation)

	// Critical changes (Red)
	if strings.Contains(translation, "⚠️") ||
		strings.Contains(translation, "CRITICAL") ||
		strings.Contains(lowerMsg, "removed") ||
		strings.Contains(lowerMsg, "required") {
		return SeverityCritical
	}

	// Safe changes (Green)
	if strings.Contains(lowerMsg, "documentation") {
		return SeveritySafe
	}

	// Everything else is moderate (Yellow)
	return SeverityModerate
}
