package runner

import (
	"fmt"
	"strings"
	"unicode"
)

// ParseServerCommand splits args (no shell).
// Supports standard quoting and escaping.
func ParseServerCommand(command string) ([]string, error) {
	if command == "" {
		return nil, fmt.Errorf("empty command")
	}

	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)
	escaped := false // track backslash escape state

	for _, r := range command {
		// Handle escaped character
		if escaped {
			// The previous character was a backslash
			current.WriteRune(r)
			escaped = false
			continue
		}

		switch {
		case r == '\\':
			if inQuote && quoteChar == '\'' {
				// Single quotes: backslash is literal
				current.WriteRune(r)
			} else {
				// Outside quotes or in double quotes: escape next char
				escaped = true
			}

		case inQuote:
			if r == quoteChar {
				inQuote = false
			} else {
				current.WriteRune(r)
			}

		case r == '"' || r == '\'':
			inQuote = true
			quoteChar = r

		case unicode.IsSpace(r):
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}

		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	if escaped {
		return nil, fmt.Errorf("trailing backslash in command")
	}

	if inQuote {
		return nil, fmt.Errorf("unclosed quote in command")
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments found in command")
	}

	return args, nil
}

// ExtractNPXArgs gets args after package name
func ExtractNPXArgs(command string) ([]string, error) {
	args, err := ParseServerCommand(command)
	if err != nil {
		return nil, err
	}

	// Find npx in the command
	npxIdx := -1
	for i, arg := range args {
		if arg == "npx" {
			npxIdx = i
			break
		}
	}

	if npxIdx == -1 {
		return nil, fmt.Errorf("not an npx command")
	}

	// Skip npx and find the package spec
	// Skip npx flags like -y, --yes, -q, --quiet, -p, --package, -c
	packageIdx := -1
	for i := npxIdx + 1; i < len(args); i++ {
		arg := args[i]
		// Skip npx flags
		if arg == "-y" || arg == "--yes" || arg == "-q" || arg == "--quiet" ||
			arg == "-p" || arg == "--package" || arg == "-c" {
			continue
		}
		// Skip flags and their values
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// This is the package spec
		packageIdx = i
		break
	}

	if packageIdx == -1 {
		return nil, fmt.Errorf("could not find package in npx command")
	}

	// Return everything after the package spec
	if packageIdx+1 < len(args) {
		return args[packageIdx+1:], nil
	}

	return []string{}, nil
}

// ValidateNoShellMetacharacters blocks shell chars
func ValidateNoShellMetacharacters(s string) error {
	// Characters that indicate shell interpretation
	dangerous := []string{";", "|", "&", "`", "\n", "\r"}
	for _, d := range dangerous {
		if strings.Contains(s, d) {
			return fmt.Errorf("command contains shell metacharacter %q", d)
		}
	}
	return nil
}

// ValidateCommandSafety blocks operators
func ValidateCommandSafety(command string) error {
	// Global bans: these are never allowed, even inside quotes
	if strings.Contains(command, "`") {
		return fmt.Errorf("shell operators not supported: found backtick (%q); pass argv directly without shell interpretation", "`")
	}

	// Patterns that indicate shell operators (check outside quotes)
	// NOTE: We only block operators that imply piping, redirection, or chaining.
	// $() and ${} are NOT blocked because without shell execution, they are
	// just literal strings passed as arguments.
	shellPatterns := []struct {
		pattern string
		desc    string
	}{
		{" | ", "pipe operator"},
		{" && ", "AND operator"},
		{" || ", "OR operator"},
		{" ; ", "command separator"},
		{" > ", "output redirect"},
		{" >> ", "append redirect"},
		{" < ", "input redirect"},
	}

	// Build a simple quote-aware scanner
	inQuote := false
	quoteChar := rune(0)
	escaped := false
	unquotedContent := &strings.Builder{}

	for _, r := range command {
		if escaped {
			escaped = false
			continue
		}

		if r == '\\' && (!inQuote || quoteChar == '"') {
			escaped = true
			continue
		}

		if inQuote {
			if r == quoteChar {
				inQuote = false
			}
			continue
		}

		if r == '"' || r == '\'' {
			inQuote = true
			quoteChar = r
			continue
		}

		unquotedContent.WriteRune(r)
	}

	unquoted := unquotedContent.String()

	for _, sp := range shellPatterns {
		if strings.Contains(unquoted, sp.pattern) {
			return fmt.Errorf("shell operators not supported: found %s (%q); pass argv directly without shell interpretation",
				sp.desc, strings.TrimSpace(sp.pattern))
		}
	}

	return nil
}

// ValidateArtifactMatch verify overrides
func ValidateArtifactMatch(pinnedName, pinnedVersion, commandOverride string) error {
	if commandOverride == "" {
		return nil
	}

	// Parse the override command to extract the package reference
	args, err := ParseServerCommand(commandOverride)
	if err != nil {
		return fmt.Errorf("failed to parse command override: %w", err)
	}

	// Find the package spec - skip common binary names and flags
	skipBinaries := map[string]bool{
		"npx": true, "docker": true, "run": true,
		"node": true, "npm": true, "env": true,
	}
	npxFlags := map[string]bool{
		"-y": true, "--yes": true, "-q": true, "--quiet": true,
		"-p": true, "--package": true, "-c": true,
	}

	for _, arg := range args {
		// Skip known binaries
		if skipBinaries[arg] {
			continue
		}
		// Skip flags
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Skip npx flags
		if npxFlags[arg] {
			continue
		}

		// Check if this looks like an npm package (scoped or unscoped)
		// Scoped packages start with @
		// Unscoped packages are words without / prefix
		if strings.HasPrefix(arg, "@") {
			// This is a scoped package
			name, version := parsePackageSpec(arg)
			if name != pinnedName {
				return fmt.Errorf("command uses package %q but lockfile pins %q", name, pinnedName)
			}
			if version != "" && version != pinnedVersion {
				return fmt.Errorf("command specifies version %q but lockfile pins %q", version, pinnedVersion)
			}
			return nil
		}

		// Could be an unscoped package or a path
		// Paths typically start with / or ./ or contain /
		if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
			// This is a path argument, skip it
			continue
		}

		// This might be an unscoped package name
		if !strings.Contains(arg, "/") || strings.Contains(arg, "@") {
			name, version := parsePackageSpec(arg)
			if name != pinnedName {
				return fmt.Errorf("command uses package %q but lockfile pins %q", name, pinnedName)
			}
			if version != "" && version != pinnedVersion {
				return fmt.Errorf("command specifies version %q but lockfile pins %q", version, pinnedVersion)
			}
			return nil
		}
	}

	return fmt.Errorf("could not find package specification in command override")
}

// parsePackageSpec splits name/version
func parsePackageSpec(spec string) (name string, version string) {
	// Handle scoped packages: @scope/package@version
	if strings.HasPrefix(spec, "@") {
		// Find the second @ which separates name from version
		restIdx := strings.Index(spec[1:], "@")
		if restIdx == -1 {
			return spec, ""
		}
		atIdx := restIdx + 1
		return spec[:atIdx], spec[atIdx+1:]
	}

	// Regular package: package@version
	atIdx := strings.LastIndex(spec, "@")
	if atIdx == -1 {
		return spec, ""
	}
	return spec[:atIdx], spec[atIdx+1:]
}
