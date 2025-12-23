package proxy

import (
	"fmt"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

func TestResponseFilter_DeletesPendingEntryAfterApply(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools: map[string]models.ToolLock{
			"safe_tool": {},
		},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	filter := NewResponseFilter(enforcer, false)

	proxyID, _ := filter.Register(1, "tools/list")

	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "safe_tool"},
				map[string]interface{}{"name": "debug_exec"},
			},
		},
	}

	_, modified := filter.Apply(resp)
	if !modified {
		t.Error("first Apply should modify response")
	}

	resp2 := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "another_tool"},
			},
		},
	}

	result2, modified2 := filter.Apply(resp2)
	if result2 != nil {
		t.Error("second Apply should DROP response (duplicate via recentUsed)")
	}
	if modified2 {
		t.Error("second Apply should NOT modify (response was dropped)")
	}
}

func TestResponseFilter_NeverMutatesErrorResponses(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools: map[string]models.ToolLock{
			"safe_tool": {},
		},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	filter := NewResponseFilter(enforcer, false)

	proxyID, _ := filter.Register(1, "tools/list")

	errorResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"error": map[string]interface{}{
			"code":    -32601,
			"message": "Method not found",
		},
	}

	filtered, modified := filter.Apply(errorResp)
	if modified {
		t.Error("error responses should never be modified (filter-wise)")
	}

	if filtered == nil {
		t.Fatal("error response should not be dropped")
	}
	if filtered["error"] == nil {
		t.Error("error field should be preserved")
	}
	if filtered["id"] != 1 {
		t.Errorf("error response ID should be rewritten to hostID (1), got %v", filtered["id"])
	}
}

func TestBridge_OutOfOrderResponses(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools: map[string]models.ToolLock{
			"tool_a": {},
			"tool_b": {},
		},
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{
				"allowed_prompt": {},
			},
		},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	filter := NewResponseFilter(enforcer, false)

	proxyID1, _ := filter.Register(1, "tools/list")
	proxyID2, _ := filter.Register(2, "prompts/list")

	resp2 := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID2,
		"result": map[string]interface{}{
			"prompts": []interface{}{
				map[string]interface{}{"name": "allowed_prompt"},
				map[string]interface{}{"name": "not_allowed_prompt"},
			},
		},
	}

	filtered2, modified2 := filter.Apply(resp2)
	if !modified2 {
		t.Error("prompts/list should be modified")
	}

	result2 := filtered2["result"].(map[string]interface{})
	prompts := result2["prompts"].([]interface{})
	if len(prompts) != 1 {
		t.Errorf("expected 1 prompt after filtering, got %d", len(prompts))
	}

	resp1 := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID1,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "tool_a"},
				map[string]interface{}{"name": "tool_c"}, // not allowed
			},
		},
	}

	filtered, modified := filter.Apply(resp1)
	if !modified {
		t.Error("tools/list should be modified")
	}

	result := filtered["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})
	if len(tools) != 1 {
		t.Errorf("expected 1 tool after filtering, got %d", len(tools))
	}
}

func TestNotification_NoIdField(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	filter := NewResponseFilter(enforcer, false)

	notification := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/tools/list_changed",
	}

	_, modified := filter.Apply(notification)
	if modified {
		t.Error("notifications should not be modified by filter")
	}
}

func TestDenyError_PreservesId(t *testing.T) {
	tests := []struct {
		name string
		id   interface{}
	}{
		{"integer id", 42},
		{"float id", float64(42)},
		{"string id", "abc-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := DenyError(tt.id, "test reason")
			if resp["id"] != tt.id {
				t.Errorf("DenyError() id = %v, want %v", resp["id"], tt.id)
			}
			if resp["jsonrpc"] != "2.0" {
				t.Error("DenyError() should have jsonrpc: 2.0")
			}
			if resp["error"] == nil {
				t.Error("DenyError() should have error field")
			}
		})
	}
}

func TestIdKey_FloatIntConsistency(t *testing.T) {
	filter := &ResponseFilter{
		pending: make(map[string]*pendingEntry),
	}

	filter.pending[idKey(42)] = &pendingEntry{method: "tools/list"}

	key := idKey(float64(42))
	if _, found := filter.pending[key]; !found {
		t.Error("idKey should match int and float64 for same numeric value")
	}
}

func TestLogBlock_NotificationFlag(t *testing.T) {
	p := &Proxy{
		cfg: Config{
			LockfilePath: "test.json",
		},
	}

	p.logBlock("tools/call", "debug_exec", "not allowed", true)
	p.logBlock("tools/call", "debug_exec", "not allowed", false)
}

func TestProxy_NotificationRequestHasNoId(t *testing.T) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		// Note: no "id" field
	}

	id := req["id"]
	isNotification := (id == nil)

	if !isNotification {
		t.Error("request without id should be detected as notification")
	}

	req2 := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
	}

	id2 := req2["id"]
	isNotification2 := (id2 == nil)

	if isNotification2 {
		t.Error("request with id should not be detected as notification")
	}
}

func TestProxy_IdNullIsRequest(t *testing.T) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      nil,
		"method":  "tools/call",
	}

	id, hasId := req["id"]
	isNotification := !hasId // Only notification if id field is MISSING

	if isNotification {
		t.Error("request with id: null should NOT be detected as notification")
	}

	if id != nil {
		t.Errorf("id should be nil, got %v", id)
	}
	if !hasId {
		t.Error("hasId should be true for id: null")
	}

	notification := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}

	_, hasIdNotif := notification["id"]
	isNotification2 := !hasIdNotif

	if !isNotification2 {
		t.Error("request without id field should be detected as notification")
	}
}

func ExampleDenyError() {
	resp := DenyError(42, "tool not in lockfile")
	fmt.Printf("id=%v error.code=%v\n", resp["id"], resp["error"].(map[string]interface{})["code"])
	// Output: id=42 error.code=-32001
}
