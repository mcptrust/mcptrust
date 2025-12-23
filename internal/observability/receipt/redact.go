// Package receipt provides redaction utilities for sensitive CLI arguments.
package receipt

import (
	"regexp"
	"strings"
)

// sensitiveFlags are flag names whose values should always be redacted.
// Both single-dash and double-dash variants are handled.
var sensitiveFlags = map[string]bool{
	"token":          true,
	"key":            true,
	"password":       true,
	"secret":         true,
	"identity-token": true,
	"pat":            true,
	"api-key":        true,
	"apikey":         true,
	"auth":           true,
	"credential":     true,
	"credentials":    true,
	"bearer":         true,
	"access-token":   true,
	"refresh-token":  true,
	"private-key":    true,
}

// sensitivePrefixes are value prefixes indicating secrets.
var sensitivePrefixes = []string{
	"sk-",         // OpenAI, Stripe
	"ghp_",        // GitHub PAT
	"github_pat_", // GitHub fine-grained PAT
	"gho_",        // GitHub OAuth
	"ghu_",        // GitHub user-to-server
	"ghs_",        // GitHub server-to-server
	"xoxb-",       // Slack bot
	"xoxp-",       // Slack user
	"AKIA",        // AWS access key
	"ya29.",       // Google OAuth
	"AIza",        // Google API key
	"npm_",        // npm token
	"pypi-",       // PyPI token
}

// jwtRegex matches JWT-like patterns (xxx.yyy.zzz where each part is base64-ish).
// This is a heuristic - may have false positives on dotted strings.
var jwtRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$`)

// longSecretRegex matches long alphanumeric strings that look like secrets.
// 32+ chars of hex or base64 characters.
var longSecretRegex = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{32,}$`)

const redactedValue = "[REDACTED]"

// RedactArgs sanitizes CLI arguments by redacting sensitive values.
// Returns the redacted args and whether any redaction was applied.
func RedactArgs(args []string) ([]string, bool) {
	if len(args) == 0 {
		return args, false
	}

	redacted := make([]string, len(args))
	wasRedacted := false

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Check for --flag=value format
		if eqIdx := strings.Index(arg, "="); eqIdx > 0 {
			flag := extractFlagName(arg[:eqIdx])
			value := arg[eqIdx+1:]

			if isSensitiveFlag(flag) || isSensitiveValue(value) {
				redacted[i] = arg[:eqIdx+1] + redactedValue
				wasRedacted = true
				continue
			}
			redacted[i] = arg
			continue
		}

		// Check for --flag value format (flag followed by value)
		if strings.HasPrefix(arg, "-") {
			flag := extractFlagName(arg)
			if isSensitiveFlag(flag) && i+1 < len(args) {
				// Next arg is the value - redact it when we get there
				redacted[i] = arg
				i++
				redacted[i] = redactedValue
				wasRedacted = true
				continue
			}
		}

		// Check if standalone value looks like a secret
		if isSensitiveValue(arg) {
			redacted[i] = redactedValue
			wasRedacted = true
			continue
		}

		redacted[i] = arg
	}

	return redacted, wasRedacted
}

// extractFlagName removes leading dashes and returns the flag name.
func extractFlagName(s string) string {
	s = strings.TrimPrefix(s, "--")
	s = strings.TrimPrefix(s, "-")
	return strings.ToLower(s)
}

// isSensitiveFlag checks if a flag name indicates a sensitive value.
func isSensitiveFlag(flag string) bool {
	return sensitiveFlags[flag]
}

// isSensitiveValue checks if a value looks like a secret by pattern matching.
func isSensitiveValue(value string) bool {
	// Check known prefixes
	for _, prefix := range sensitivePrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	// Check JWT-like pattern
	if jwtRegex.MatchString(value) {
		return true
	}

	// Check long secret-like strings (only if they start with certain patterns)
	// Be conservative to avoid false positives on paths/URLs
	if len(value) >= 32 && !strings.Contains(value, "/") && !strings.Contains(value, ".") {
		if longSecretRegex.MatchString(value) {
			return true
		}
	}

	return false
}
