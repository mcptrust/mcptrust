package locker

import (
	"crypto/sha256"
	"fmt"
)

// HashString sha256
func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("sha256:%x", hash)
}

// HashJSON canonical sha256
func HashJSON(v interface{}) (string, error) {
	if v == nil {
		return "", nil
	}

	// empty map check
	if m, ok := v.(map[string]interface{}); ok && len(m) == 0 {
		return "", nil
	}

	canonical, err := CanonicalizeJSON(v)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	hash := sha256.Sum256(canonical)
	return fmt.Sprintf("sha256:%x", hash), nil
}

// CanonicalizeJSON v1
func CanonicalizeJSON(v interface{}) ([]byte, error) {
	return CanonicalizeJSONv1(v)
}
