package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

func generateProxyID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return "mcp_" + hex.EncodeToString(buf[:]), nil
}

type pendingEntry struct {
	method string
	hostID interface{}
}

type usedEntry struct {
	usedAt time.Time
}

// ResponseFilter manages ID translation for request/response correlation
type ResponseFilter struct {
	enforcer     *Enforcer
	auditOnly    bool
	pending      map[string]*pendingEntry
	recentUsed   map[string]*usedEntry
	pruneCounter int
	mu           sync.Mutex
}

func NewResponseFilter(enforcer *Enforcer, auditOnly bool) *ResponseFilter {
	return &ResponseFilter{
		enforcer:   enforcer,
		auditOnly:  auditOnly,
		pending:    make(map[string]*pendingEntry),
		recentUsed: make(map[string]*usedEntry),
	}
}

func (f *ResponseFilter) Register(hostID interface{}, method string) (string, error) {
	if err := ValidateHostID(hostID); err != nil {
		return "", err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.pending) >= MaxPendingRequests {
		return "", ErrPendingMapFull
	}

	for i := 0; i < 3; i++ {
		proxyID, err := generateProxyID()
		if err != nil {
			return "", err
		}

		if _, exists := f.pending[proxyID]; exists {
			continue
		}
		if _, used := f.recentUsed[proxyID]; used {
			continue
		}

		f.pending[proxyID] = &pendingEntry{method: method, hostID: hostID}
		return proxyID, nil
	}

	return "", fmt.Errorf("failed to generate unique proxyID after retries")
}

func (f *ResponseFilter) Apply(resp map[string]interface{}) (map[string]interface{}, bool) {
	id, hasID := resp["id"]
	if !hasID {
		if _, hasResult := resp["result"]; hasResult {
			return nil, false
		}
		if _, hasError := resp["error"]; hasError {
			return nil, false
		}
		return resp, false
	}

	_, hasError := resp["error"]
	_, hasResult := resp["result"]
	if hasError && hasResult {
		delete(resp, "result")
	}

	proxyID, ok := id.(string)
	if !ok {
		return nil, false
	}

	f.mu.Lock()

	// Check for duplicate (already processed)
	if _, wasUsed := f.recentUsed[proxyID]; wasUsed {
		f.mu.Unlock()
		return nil, false // SEC-04: Drop duplicate
	}

	entry, found := f.pending[proxyID]
	if !found {
		f.mu.Unlock()
		return nil, false
	}

	// First valid response: delete from pending, add to recentUsed
	delete(f.pending, proxyID)
	f.recentUsed[proxyID] = &usedEntry{usedAt: time.Now()}
	f.pruneCounter++

	// Prune recentUsed periodically (amortized O(1))
	if len(f.recentUsed) > MaxRecentUsedIDs && f.pruneCounter >= 256 {
		f.pruneRecentUsed()
		f.pruneCounter = 0
	}

	f.mu.Unlock()

	resp["id"] = entry.hostID

	if hasError {
		return resp, false
	}

	if f.auditOnly {
		return resp, false
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return resp, false
	}

	switch entry.method {
	case "tools/list":
		filtered := filterToolsList(result, f.enforcer.allowedTools)
		resp["result"] = filtered
		return resp, true

	case "prompts/list":
		filtered := filterPromptsList(result, f.enforcer.allowedPrompts)
		resp["result"] = filtered
		return resp, true

	case "resources/templates/list":
		filtered := filterTemplatesList(result, f.enforcer.allowedTemplateURIs)
		resp["result"] = filtered
		return resp, true

	case "resources/list":
		if f.enforcer.allowStaticResources {
			filtered := filterResourcesList(result, f.enforcer.staticResources)
			resp["result"] = filtered
			return resp, true
		}
	}

	return resp, false
}

// pruneRecentUsed removes expired entries (called with lock held)
func (f *ResponseFilter) pruneRecentUsed() {
	cutoff := time.Now().Add(-UsedIDTTL)

	// Phase 1: Remove expired entries
	for key, entry := range f.recentUsed {
		if entry.usedAt.Before(cutoff) {
			delete(f.recentUsed, key)
		}
	}

	for len(f.recentUsed) > MaxRecentUsedIDs {
		var oldestKey string
		var oldestTime time.Time
		first := true

		// Find oldest entry
		for key, entry := range f.recentUsed {
			if first || entry.usedAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.usedAt
				first = false
			}
		}

		if oldestKey != "" {
			delete(f.recentUsed, oldestKey)
		} else {
			break // safety: shouldn't happen
		}
	}
}

func (f *ResponseFilter) ClearPending() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = make(map[string]*pendingEntry)
	f.recentUsed = make(map[string]*usedEntry)
}

func (f *ResponseFilter) PendingCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending)
}

func (f *ResponseFilter) RecentUsedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.recentUsed)
}

func filterToolsList(result map[string]interface{}, allowed map[string]struct{}) map[string]interface{} {
	tools, ok := result["tools"].([]interface{})
	if !ok {
		return result
	}

	filtered := make([]interface{}, 0, len(tools))
	for _, t := range tools {
		tool, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := tool["name"].(string)
		if _, found := allowed[name]; found {
			filtered = append(filtered, tool)
		}
	}

	return map[string]interface{}{
		"tools": filtered,
	}
}

func filterPromptsList(result map[string]interface{}, allowed map[string]struct{}) map[string]interface{} {
	prompts, ok := result["prompts"].([]interface{})
	if !ok {
		return result
	}

	filtered := make([]interface{}, 0, len(prompts))
	for _, p := range prompts {
		prompt, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := prompt["name"].(string)
		if _, found := allowed[name]; found {
			filtered = append(filtered, prompt)
		}
	}

	return map[string]interface{}{
		"prompts": filtered,
	}
}

func filterTemplatesList(result map[string]interface{}, allowedURIs map[string]struct{}) map[string]interface{} {
	templates, ok := result["resourceTemplates"].([]interface{})
	if !ok {
		return result
	}

	filtered := make([]interface{}, 0, len(templates))
	for _, t := range templates {
		tmpl, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		uri, _ := tmpl["uriTemplate"].(string)
		if _, found := allowedURIs[uri]; found {
			filtered = append(filtered, tmpl)
		}
	}

	return map[string]interface{}{
		"resourceTemplates": filtered,
	}
}

func filterResourcesList(result map[string]interface{}, allowed map[string]struct{}) map[string]interface{} {
	resources, ok := result["resources"].([]interface{})
	if !ok {
		return result
	}

	filtered := make([]interface{}, 0, len(resources))
	for _, r := range resources {
		res, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		uri, _ := res["uri"].(string)
		if _, found := allowed[uri]; found {
			filtered = append(filtered, res)
		}
	}

	return map[string]interface{}{
		"resources": filtered,
	}
}

func idKey(id interface{}) string {
	switch v := id.(type) {
	case json.Number:
		// DoS protection: reject excessively long ID literals
		if len(v) > MaxIDLiteralBytes {
			return "s:" + string(v)
		}
		if key, ok := canonicalizeJSONNumber(string(v)); ok {
			return key
		}
		return "s:" + string(v)
	case float64:
		lit := strconv.FormatFloat(v, 'g', -1, 64)
		if key, ok := canonicalizeJSONNumber(lit); ok {
			return key
		}
		return canonicalizeNumber(v)
	case int:
		return "n:" + strconv.Itoa(v)
	case int64:
		return "n:" + strconv.FormatInt(v, 10)
	case string:
		if len(v) > MaxIDLiteralBytes {
			return "s:" + v
		}
		if key, ok := canonicalizeJSONNumber(v); ok {
			return key
		}
		return "s:" + v
	case nil:
		return "<nil>"
	default:
		return "u:" + fmt.Sprintf("%v", v)
	}
}

func canonicalizeNumber(v float64) string {
	if v == float64(int64(v)) {
		return "n:" + strconv.FormatInt(int64(v), 10)
	}
	return "n:" + strconv.FormatFloat(v, 'f', -1, 64)
}
