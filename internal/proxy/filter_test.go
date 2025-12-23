package proxy

import (
	"encoding/json"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

func TestFilterToolsList(t *testing.T) {
	allowed := map[string]struct{}{
		"safe_tool": {},
	}

	input := map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":        "safe_tool",
				"description": "A safe tool",
				"inputSchema": map[string]interface{}{"type": "object"},
			},
			map[string]interface{}{
				"name":        "debug_exec",
				"description": "Dangerous tool",
				"inputSchema": map[string]interface{}{"type": "object"},
			},
		},
	}

	result := filterToolsList(input, allowed)
	tools := result["tools"].([]interface{})

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	tool := tools[0].(map[string]interface{})
	if tool["name"] != "safe_tool" {
		t.Errorf("expected safe_tool, got %v", tool["name"])
	}

	if tool["inputSchema"] == nil {
		t.Error("expected inputSchema to be preserved")
	}
}

func TestFilterPromptsList(t *testing.T) {
	allowed := map[string]struct{}{
		"safe_prompt": {},
	}

	input := map[string]interface{}{
		"prompts": []interface{}{
			map[string]interface{}{
				"name":        "safe_prompt",
				"description": "A safe prompt",
				"arguments":   []interface{}{map[string]interface{}{"name": "topic"}},
			},
			map[string]interface{}{
				"name":        "evil_prompt",
				"description": "Evil prompt",
			},
		},
	}

	result := filterPromptsList(input, allowed)
	prompts := result["prompts"].([]interface{})

	if len(prompts) != 1 {
		t.Fatalf("expected 1 prompt, got %d", len(prompts))
	}

	prompt := prompts[0].(map[string]interface{})
	if prompt["name"] != "safe_prompt" {
		t.Errorf("expected safe_prompt, got %v", prompt["name"])
	}

	if prompt["arguments"] == nil {
		t.Error("expected arguments to be preserved")
	}
}

func TestFilterTemplatesList(t *testing.T) {
	allowed := map[string]struct{}{
		"db://{id}": {},
	}

	input := map[string]interface{}{
		"resourceTemplates": []interface{}{
			map[string]interface{}{
				"uriTemplate": "db://{id}",
				"name":        "Database",
				"mimeType":    "application/json",
			},
			map[string]interface{}{
				"uriTemplate": "file:///{path}",
				"name":        "Files",
			},
		},
	}

	result := filterTemplatesList(input, allowed)
	templates := result["resourceTemplates"].([]interface{})

	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}

	tmpl := templates[0].(map[string]interface{})
	if tmpl["uriTemplate"] != "db://{id}" {
		t.Errorf("expected db://{id}, got %v", tmpl["uriTemplate"])
	}

	if tmpl["mimeType"] != "application/json" {
		t.Error("expected mimeType to be preserved")
	}
}

func TestFilterResourcesList(t *testing.T) {
	allowed := map[string]struct{}{
		"static://config.json": {},
	}

	input := map[string]interface{}{
		"resources": []interface{}{
			map[string]interface{}{
				"uri":      "static://config.json",
				"name":     "Config",
				"mimeType": "application/json",
			},
			map[string]interface{}{
				"uri":  "private://secret.txt",
				"name": "Secret",
			},
		},
	}

	result := filterResourcesList(input, allowed)
	resources := result["resources"].([]interface{})

	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	res := resources[0].(map[string]interface{})
	if res["uri"] != "static://config.json" {
		t.Errorf("expected static://config.json, got %v", res["uri"])
	}
}

func TestResponseFilter_Apply(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools: map[string]models.ToolLock{
			"safe_tool": {},
		},
		Prompts: models.PromptsSection{
			Definitions: map[string]models.PromptDefinition{
				"safe_prompt": {},
			},
		},
		Resources: models.ResourcesSection{
			Templates: []models.ResourceTemplateLock{
				{URITemplate: "db://{id}"},
			},
		},
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

	filtered, modified := filter.Apply(resp)
	if !modified {
		t.Error("expected response to be modified")
	}

	if filtered["id"] != 1 {
		t.Errorf("ID should be rewritten to hostID 1, got %v", filtered["id"])
	}

	result := filtered["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool after filtering, got %d", len(tools))
	}
}

func TestResponseFilter_NoFilterRegistered(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "unknown_id",
		"result":  map[string]interface{}{"tools": []interface{}{}},
	}

	result, modified := filter.Apply(resp)
	if result != nil {
		t.Error("expected unknown ID response to be dropped (nil)")
	}
	if modified {
		t.Error("expected modified=false when response is dropped")
	}
}

func TestIdKey(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		{"float64 whole", float64(42), "n:42"},
		{"int", 42, "n:42"},
		{"int64", int64(42), "n:42"},
		{"float64 fraction", float64(1.5), "n:1.5"},

		{"negative int", -1, "n:-1"},
		{"negative float64", float64(-1), "n:-1"},
		{"negative fraction", float64(-1.5), "n:-1.5"},

		{"canonical string", "42", "n:42"},
		{"negative canonical string", "-5", "n:-5"},
		{"negative one string", "-1", "n:-1"},

		{"leading zero", "01", "s:01"},
		{"leading zeros", "007", "s:007"},
		{"plus sign", "+1", "s:+1"},
		{"trailing whitespace", "1 ", "s:1 "}, // has trailing space - not valid JSON

		{"exponent notation", "1e3", "n:1000"},
		{"decimal string", "1.5", "n:1.5"},
		{"leading whitespace", " 1", "n:1"},

		{"string", "abc", "s:abc"},
		{"uuid string", "abc-123-def", "s:abc-123-def"},

		{"zero", "0", "n:0"},
		{"negative zero", "-0", "n:0"},
		{"nil becomes <nil>", nil, "<nil>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := idKey(tt.input)
			if got != tt.want {
				t.Errorf("idKey(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIdKey_CanonicalizeNumericStrings(t *testing.T) {
	tests := []interface{}{
		1,
		int64(1),
		float64(1),
		float64(1.0),
		"1",
	}

	expected := "n:1"
	for _, id := range tests {
		got := idKey(id)
		if got != expected {
			t.Errorf("idKey(%T %v) = %q, want %q", id, id, got, expected)
		}
	}
}

func TestIdKey_NoCollisions(t *testing.T) {
	tests := []struct {
		a, b interface{}
	}{
		{"01", 1},
		{"007", 7},
		{"+1", 1},
		{"abc", "123"},
	}

	for _, tt := range tests {
		aKey := idKey(tt.a)
		bKey := idKey(tt.b)
		if aKey == bKey {
			t.Errorf("COLLISION: idKey(%T %v) = %q == idKey(%T %v) = %q",
				tt.a, tt.a, aKey, tt.b, tt.b, bKey)
		}
	}
}

func TestIdKey_FractionalIDs(t *testing.T) {
	// 1.5 as float64 should NOT collapse to n:1
	got := idKey(float64(1.5))
	if got == "n:1" {
		t.Error("float64(1.5) should NOT collapse to n:1")
	}
	if got != "n:1.5" {
		t.Errorf("idKey(1.5) = %q, want n:1.5", got)
	}

	got2 := idKey("1.5")
	if got2 != "n:1.5" {
		t.Errorf("idKey(\"1.5\") = %q, want n:1.5 (representation invariant)", got2)
	}

	if got != got2 {
		t.Errorf("float64(1.5) and string \"1.5\" should produce same key, got %q vs %q", got, got2)
	}
}

func TestIdKey_JsonNumber(t *testing.T) {
	tests := []struct {
		input json.Number
		want  string
	}{
		{json.Number("42"), "n:42"},
		{json.Number("-5"), "n:-5"},
		{json.Number("1.5"), "n:1.5"},
		{json.Number("0"), "n:0"},
	}

	for _, tt := range tests {
		got := idKey(tt.input)
		if got != tt.want {
			t.Errorf("idKey(json.Number(%q)) = %q, want %q", string(tt.input), got, tt.want)
		}
	}
}

func TestIdKey_LargeNumbers(t *testing.T) {
	maxSafe := float64(9007199254740992)
	got := idKey(maxSafe)
	if got != "n:9007199254740992" {
		t.Errorf("idKey(2^53) = %q, want n:9007199254740992", got)
	}

	largeNum := json.Number("9007199254740993")
	gotLarge := idKey(largeNum)

	t.Logf("idKey(json.Number(\"9007199254740993\")) = %q", gotLarge)

	safeNum := json.Number("12345")
	gotSafe := idKey(safeNum)
	if gotSafe != "n:12345" {
		t.Errorf("idKey(json.Number(\"12345\")) = %q, want n:12345", gotSafe)
	}

	negNum := json.Number("-42")
	gotNeg := idKey(negNum)
	if gotNeg != "n:-42" {
		t.Errorf("idKey(json.Number(\"-42\")) = %q, want n:-42", gotNeg)
	}
}

func TestResponseShapeValidation_ErrorAndResultNormalized(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{"safe_tool": {}},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	proxyID, _ := filter.Register(1, "tools/list")

	malformedResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"error": map[string]interface{}{
			"code":    -32600,
			"message": "Invalid Request",
		},
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "evil_tool"},
			},
		},
	}

	filtered, modified := filter.Apply(malformedResp)
	if filtered == nil {
		t.Fatal("Response should not be dropped")
	}
	if modified {
		t.Error("Error responses should not be modified (filtering-wise)")
	}

	if filtered["result"] != nil {
		t.Error("result field should be stripped from error+result response")
	}

	if filtered["error"] == nil {
		t.Error("error field should be preserved")
	}
	if filtered["id"] != 1 {
		t.Errorf("ID should be rewritten to hostID (1), got %v", filtered["id"])
	}
}

func TestResponseFilter_DropsInvalidNotifications(t *testing.T) {
	enforcer, _ := NewEnforcer(&models.LockfileV3{}, false)
	filter := NewResponseFilter(enforcer, false)

	invalidResult := map[string]interface{}{
		"jsonrpc": "2.0",
		"result":  map[string]interface{}{"foo": "bar"},
	}
	res1, _ := filter.Apply(invalidResult)
	if res1 != nil {
		t.Error("Should drop result without ID")
	}

	invalidError := map[string]interface{}{
		"jsonrpc": "2.0",
		"error":   map[string]interface{}{"code": -1},
	}
	res2, _ := filter.Apply(invalidError)
	if res2 != nil {
		t.Error("Should drop error without ID")
	}

	legitNotify := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/test",
		"params":  map[string]interface{}{},
	}
	res3, _ := filter.Apply(legitNotify)
	if res3 == nil {
		t.Error("Should pass legit notification")
	}
}

func TestIDTranslation_SpoofAttemptDropped(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{"safe_tool": {}},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	proxyID, _ := filter.Register("1", "tools/list")

	spoofResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "some_other_id",
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "evil_tool"},
			},
		},
	}

	filtered, _ := filter.Apply(spoofResp)
	if filtered != nil {
		t.Fatal("spoofed response should be dropped")
	}

	correctResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "safe_tool"},
				map[string]interface{}{"name": "evil_tool"},
			},
		},
	}

	filtered2, wasFiltered := filter.Apply(correctResp)
	if !wasFiltered {
		t.Error("Correct response should be filtered")
	}
	if filtered2 == nil {
		t.Fatal("Correct response should not be dropped")
	}

	tools := filtered2["result"].(map[string]interface{})["tools"].([]interface{})
	if len(tools) != 1 {
		t.Errorf("Expected 1 tool after filtering, got %d", len(tools))
	}
}

func TestIDTranslation_LongHostIDRejected(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{"allowed_tool": {}},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	longHostID := "host-request-" + string(make([]byte, 300))

	_, err := filter.Register(longHostID, "tools/list")
	if err != ErrHostIDTooLarge {
		t.Errorf("Register with long hostID should return ErrHostIDTooLarge, got: %v", err)
	}
}

func TestResponseFilter_DuplicateResponseDropped(t *testing.T) {
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

	proxyID, err := filter.Register(7, "tools/list")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	resp1 := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "safe_tool"},
				map[string]interface{}{"name": "debug_exec"},
			},
		},
	}

	filtered1, modified1 := filter.Apply(resp1)
	if !modified1 {
		t.Error("first response should be modified")
	}
	tools := filtered1["result"].(map[string]interface{})["tools"].([]interface{})
	if len(tools) != 1 {
		t.Errorf("first response should filter to 1 tool, got %d", len(tools))
	}

	resp2 := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "evil_tool"},
				map[string]interface{}{"name": "debug_exec"},
			},
		},
	}

	filtered2, _ := filter.Apply(resp2)
	if filtered2 != nil {
		t.Error("second response should be dropped (return nil)")
	}
}

func TestResponseFilter_SpoofPrevention(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools: map[string]models.ToolLock{
			"allowed": {},
		},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	proxyID, _ := filter.Register(42, "tools/list")

	decoy := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "allowed"},
			},
		},
	}
	filter.Apply(decoy) // consumed

	unfiltered := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "allowed"},
				map[string]interface{}{"name": "evil_tool"},
				map[string]interface{}{"name": "another_evil"},
			},
		},
	}

	result, _ := filter.Apply(unfiltered)
	if result != nil {
		t.Error("second response should be dropped to prevent spoof attack")
	}
}

func TestRegister_ReturnsError(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	_, err := filter.Register(1, "tools/list")
	if err != nil {
		t.Errorf("first Register should not error: %v", err)
	}
}

func TestPendingEntriesDeletedAfterResponse(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{"allowed": {}},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	filter := NewResponseFilter(enforcer, false)

	for i := 0; i < 2000; i++ {
		proxyID, err := filter.Register(i, "tools/list")
		if err != nil {
			t.Fatalf("Register(%d) failed after response cycle: %v", i, err)
		}

		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      proxyID,
			"result": map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{"name": "allowed"},
				},
			},
		}
		filter.Apply(resp)
	}

	if filter.PendingCount() != 0 {
		t.Errorf("pending count = %d, want 0 (entries should be deleted after response)", filter.PendingCount())
	}

	if filter.RecentUsedCount() == 0 {
		t.Error("recentUsed should have entries for duplicate detection")
	}
}

func TestDuplicateAfterDeleteStillDropped(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{"allowed": {}},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	filter := NewResponseFilter(enforcer, false)

	proxyID, _ := filter.Register(42, "tools/list")

	firstResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "allowed"},
			},
		},
	}
	result1, _ := filter.Apply(firstResp)
	if result1 == nil {
		t.Fatal("first response should not be dropped")
	}

	if filter.PendingCount() != 0 {
		t.Errorf("pending count = %d, want 0 after response", filter.PendingCount())
	}

	if filter.RecentUsedCount() != 1 {
		t.Errorf("recentUsed count = %d, want 1", filter.RecentUsedCount())
	}

	duplicateResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "evil_tool"},
			},
		},
	}
	result2, _ := filter.Apply(duplicateResp)
	if result2 != nil {
		t.Error("SEC-04 REGRESSION: duplicate should still be dropped even after entry deleted from pending")
	}
}

func TestRecentUsedBoundedGrowth(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{"allowed": {}},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	filter := NewResponseFilter(enforcer, false)

	numRequests := MaxRecentUsedIDs * 3

	for i := 0; i < numRequests; i++ {
		proxyID, err := filter.Register(i, "tools/list")
		if err != nil {
			t.Fatalf("Register(%d) failed: %v", i, err)
		}

		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      proxyID,
			"result": map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{"name": "allowed"},
				},
			},
		}
		filter.Apply(resp)

		maxAllowed := MaxRecentUsedIDs + 256
		if filter.RecentUsedCount() > maxAllowed {
			t.Fatalf("UNBOUNDED GROWTH: recentUsed = %d, max allowed = %d (at i=%d)",
				filter.RecentUsedCount(), maxAllowed, i)
		}
	}

	maxAllowed := MaxRecentUsedIDs + 256
	if filter.RecentUsedCount() > maxAllowed {
		t.Errorf("Final recentUsed = %d, should be <= %d", filter.RecentUsedCount(), maxAllowed)
	}
}

func TestClearPendingClearsBoth(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{"allowed": {}},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}

	enforcer, err := NewEnforcer(lockfile, false)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	filter := NewResponseFilter(enforcer, false)

	for i := 0; i < 100; i++ {
		proxyID, _ := filter.Register(i, "tools/list")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      proxyID,
			"result":  map[string]interface{}{"tools": []interface{}{}},
		}
		filter.Apply(resp)
	}

	if filter.RecentUsedCount() != 100 {
		t.Errorf("recentUsed = %d, want 100", filter.RecentUsedCount())
	}

	filter.ClearPending()

	if filter.RecentUsedCount() != 0 {
		t.Errorf("after ClearPending, recentUsed = %d, want 0", filter.RecentUsedCount())
	}
	if filter.PendingCount() != 0 {
		t.Errorf("after ClearPending, pending = %d, want 0", filter.PendingCount())
	}
}

func TestAuditOnly_StillDropsUnknownResponses(t *testing.T) {
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

	filter := NewResponseFilter(enforcer, true)

	proxyID, _ := filter.Register(1, "tools/list")

	spoofedResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "mcp_deadbeefdeadbeefdeadbeefdeadbeef",
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "evil_tool"},
			},
		},
	}

	result, _ := filter.Apply(spoofedResp)
	if result != nil {
		t.Fatal("SECURITY FAILURE: audit-only mode MUST drop unknown proxyIDs")
	}

	legitimateResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "safe_tool"},
				map[string]interface{}{"name": "debug_exec"},
			},
		},
	}

	result1, modified := filter.Apply(legitimateResp)
	if result1 == nil {
		t.Fatal("First legitimate response should not be dropped")
	}
	if modified {
		t.Error("audit-only mode should NOT modify/filter list responses")
	}

	tools := result1["result"].(map[string]interface{})["tools"].([]interface{})
	if len(tools) != 2 {
		t.Errorf("audit-only should NOT filter, expected 2 tools, got %d", len(tools))
	}

	if result1["id"] != 1 {
		t.Errorf("ID should be rewritten to hostID (1), got %v", result1["id"])
	}

	replayResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "injected_evil"},
			},
		},
	}

	result2, _ := filter.Apply(replayResp)
	if result2 != nil {
		t.Fatal("SECURITY FAILURE: audit-only mode MUST drop duplicate proxyIDs")
	}
}

func TestRegister_RejectsHugeStringHostID(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	hugeID := string(make([]byte, MaxHostIDBytes+1))
	for i := range hugeID {
		hugeID = hugeID[:i] + "x" + hugeID[i+1:]
	}

	_, err := filter.Register(hugeID, "tools/list")
	if err != ErrHostIDTooLarge {
		t.Errorf("Register with oversized string ID should return ErrHostIDTooLarge, got: %v", err)
	}
}

func TestRegister_AcceptsBoundarySizes(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	exactID := string(make([]byte, MaxHostIDBytes))
	for i := range exactID {
		exactID = exactID[:i] + "a" + exactID[i+1:]
	}
	_, err := filter.Register(exactID, "tools/list")
	if err != nil {
		t.Errorf("Register with exactly MaxHostIDBytes should succeed, got: %v", err)
	}

	tooLongID := exactID + "x"
	_, err = filter.Register(tooLongID, "tools/list")
	if err != ErrHostIDTooLarge {
		t.Errorf("Register with MaxHostIDBytes+1 should return ErrHostIDTooLarge, got: %v", err)
	}
}

func TestRegister_RejectsObjectOrArrayID(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	objectID := map[string]interface{}{"nested": "id"}
	_, err := filter.Register(objectID, "tools/list")
	if err != ErrHostIDInvalidType {
		t.Errorf("Register with object ID should return ErrHostIDInvalidType, got: %v", err)
	}

	arrayID := []interface{}{"element1", "element2"}
	_, err = filter.Register(arrayID, "tools/list")
	if err != ErrHostIDInvalidType {
		t.Errorf("Register with array ID should return ErrHostIDInvalidType, got: %v", err)
	}
}

func TestRegister_AcceptsValidIDTypes(t *testing.T) {
	lockfile := &models.LockfileV3{
		Tools:     map[string]models.ToolLock{},
		Prompts:   models.PromptsSection{Definitions: map[string]models.PromptDefinition{}},
		Resources: models.ResourcesSection{Templates: []models.ResourceTemplateLock{}},
	}
	enforcer, _ := NewEnforcer(lockfile, false)

	validIDs := []interface{}{
		nil,                     // null
		"valid-string-id",       // string
		json.Number("12345"),    // json.Number
		float64(42.5),           // float64
		42,                      // int
		int64(9007199254740992), // int64
	}

	for _, id := range validIDs {
		filter := NewResponseFilter(enforcer, false) // fresh filter for each
		_, err := filter.Register(id, "tools/list")
		if err != nil {
			t.Errorf("Register with valid ID %T should succeed, got: %v", id, err)
		}
	}
}
