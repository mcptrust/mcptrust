package proxy

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/mcptrust/mcptrust/internal/models"
)

// Enforcer manages allowlists and template matching
type Enforcer struct {
	allowedTools         map[string]struct{}
	allowedPrompts       map[string]struct{}
	allowedTemplateURIs  map[string]struct{}
	templateMatchers     []*regexp.Regexp
	staticResources      map[string]struct{}
	allowStaticResources bool
	mu                   sync.RWMutex
}

// NewEnforcer creates an enforcer from a v3 lockfile
func NewEnforcer(lockfile *models.LockfileV3, allowStaticResources bool) (*Enforcer, error) {
	e := &Enforcer{
		allowedTools:         make(map[string]struct{}),
		allowedPrompts:       make(map[string]struct{}),
		allowedTemplateURIs:  make(map[string]struct{}),
		templateMatchers:     make([]*regexp.Regexp, 0),
		staticResources:      make(map[string]struct{}),
		allowStaticResources: allowStaticResources,
	}

	// Build tools allowlist
	for name := range lockfile.Tools {
		e.allowedTools[name] = struct{}{}
	}

	// Build prompts allowlist
	for name := range lockfile.Prompts.Definitions {
		e.allowedPrompts[name] = struct{}{}
	}

	// Build template matchers
	for _, tmpl := range lockfile.Resources.Templates {
		e.allowedTemplateURIs[tmpl.URITemplate] = struct{}{}

		matcher, err := CompileTemplateMatcher(tmpl.URITemplate)
		if err != nil {
			return nil, fmt.Errorf("failed to compile template %q: %w", tmpl.URITemplate, err)
		}
		e.templateMatchers = append(e.templateMatchers, matcher)
	}

	return e, nil
}

// AllowTool checks if a tool name is in the allowlist
func (e *Enforcer) AllowTool(name string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, found := e.allowedTools[name]
	return found
}

// AllowPrompt checks if a prompt name is in the allowlist
func (e *Enforcer) AllowPrompt(name string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, found := e.allowedPrompts[name]
	return found
}

// AllowResourceURI checks if a URI matches any locked template or static resource
func (e *Enforcer) AllowResourceURI(uri string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check template matchers
	for _, matcher := range e.templateMatchers {
		if matcher.MatchString(uri) {
			return true
		}
	}

	// Check static resources if enabled
	if e.allowStaticResources {
		if _, found := e.staticResources[uri]; found {
			return true
		}
	}

	return false
}

// SetStaticResources sets the static resource allowlist from startup
func (e *Enforcer) SetStaticResources(uris []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, uri := range uris {
		e.staticResources[uri] = struct{}{}
	}
}

// CompileTemplateMatcher converts a URI template to a regex.
// Supports basic {var} placeholders, rejects unsupported RFC6570 operators.
// The FINAL placeholder uses (.+) to match multi-segment paths (e.g., file:///a/b/c).
// Non-final placeholders use ([^/]+) for single segments only.
func CompileTemplateMatcher(template string) (*regexp.Regexp, error) {
	// Check for unsupported RFC6570 operators
	if strings.Contains(template, "{+") || strings.Contains(template, "{?") ||
		strings.Contains(template, "{#") || strings.Contains(template, "{.") ||
		strings.Contains(template, "{/") || strings.Contains(template, "{;") ||
		strings.Contains(template, "{&") {
		return nil, fmt.Errorf("unsupported RFC6570 operator in template")
	}

	// Escape regex special chars except our placeholders
	escaped := regexp.QuoteMeta(template)

	// Find all placeholder positions
	re := regexp.MustCompile(`\\{([^}]+)\\}`)
	matches := re.FindAllStringIndex(escaped, -1)

	if len(matches) == 0 {
		// No placeholders, just match literally
		return regexp.Compile("^" + escaped + "$")
	}

	// Replace placeholders: final one uses (.+), others use ([^/]+)
	var result strings.Builder
	lastEnd := 0
	for i, match := range matches {
		result.WriteString(escaped[lastEnd:match[0]])
		if i == len(matches)-1 {
			// Final placeholder: allow multi-segment paths
			result.WriteString(`(.+)`)
		} else {
			// Non-final: single segment only
			result.WriteString(`([^/]+)`)
		}
		lastEnd = match[1]
	}
	result.WriteString(escaped[lastEnd:])

	// Anchor pattern
	pattern := "^" + result.String() + "$"

	return regexp.Compile(pattern)
}
