package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

// Red team tests for proxy security invariants

func TestProxy_RedTeam_HugeHostIDRejected(t *testing.T) {
	lockfile := &models.LockfileV3{Tools: map[string]models.ToolLock{}}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	hugeID := string(make([]byte, MaxHostIDBytes+1))
	_, err := filter.Register(hugeID, "tools/list")
	if err != ErrHostIDTooLarge {
		t.Fatalf("expected ErrHostIDTooLarge, got %v", err)
	}
}

func TestProxy_RedTeam_ObjectArrayIDRejected(t *testing.T) {
	lockfile := &models.LockfileV3{Tools: map[string]models.ToolLock{}}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	// object as ID
	objID := map[string]interface{}{"foo": "bar"}
	_, err := filter.Register(objID, "tools/list")
	if err != ErrHostIDInvalidType {
		t.Errorf("expected ErrHostIDInvalidType for object, got %v", err)
	}

	// array as ID
	arrID := []interface{}{"foo", "bar"}
	_, err = filter.Register(arrID, "tools/list")
	if err != ErrHostIDInvalidType {
		t.Errorf("expected ErrHostIDInvalidType for array, got %v", err)
	}
}

func TestProxy_RedTeam_PendingSaturationFailClosed(t *testing.T) {
	lockfile := &models.LockfileV3{Tools: map[string]models.ToolLock{}}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	// fill pending map
	for i := 0; i < MaxPendingRequests; i++ {
		_, err := filter.Register(i, "tools/list")
		if err != nil {
			t.Fatalf("setup failed at %d: %v", i, err)
		}
	}

	// one more should fail
	_, err := filter.Register("overflow", "tools/list")
	if err != ErrPendingMapFull {
		t.Fatalf("expected ErrPendingMapFull, got %v", err)
	}
}

func TestProxy_RedTeam_AuditOnlyDropsUnknownProxyIDs(t *testing.T) {
	lockfile := &models.LockfileV3{Tools: map[string]models.ToolLock{}}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, true) // auditOnly

	// spoofed response with unknown proxyID
	spoofedResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "mcp_unknown12345",
		"result":  map[string]interface{}{"tools": []interface{}{}},
	}

	result, _ := filter.Apply(spoofedResp)
	if result != nil {
		t.Fatal("audit mode should still drop unknown proxyIDs")
	}
}

func TestProxy_RedTeam_ServerInjectionDropped(t *testing.T) {
	lockfile := &models.LockfileV3{Tools: map[string]models.ToolLock{}}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	// result without id should be dropped
	injection := map[string]interface{}{
		"jsonrpc": "2.0",
		"result":  map[string]interface{}{"hacked": true},
	}
	result, _ := filter.Apply(injection)
	if result != nil {
		t.Fatal("result without id should be dropped")
	}

	// error without id should also be dropped
	errInjection := map[string]interface{}{
		"jsonrpc": "2.0",
		"error":   map[string]interface{}{"code": -32000},
	}
	result, _ = filter.Apply(errInjection)
	if result != nil {
		t.Fatal("error without id should be dropped")
	}
}

func TestProxy_RedTeam_IdNullHandledSafely(t *testing.T) {
	lockfile := &models.LockfileV3{Tools: map[string]models.ToolLock{}}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	// id:null is valid JSON-RPC
	proxyID, err := filter.Register(nil, "tools/list")
	if err != nil {
		t.Fatalf("Register(nil) failed: %v", err)
	}

	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      proxyID,
		"result":  map[string]interface{}{"foo": "bar"},
	}

	validated, _ := filter.Apply(resp)
	if validated == nil {
		t.Fatal("valid response for id:null was dropped")
	}
	if validated["id"] != nil {
		t.Errorf("expected id:nil, got %v", validated["id"])
	}
}

func TestProxy_RedTeam_LargeJsonNumberRejected(t *testing.T) {
	lockfile := &models.LockfileV3{Tools: map[string]models.ToolLock{}}
	enforcer, _ := NewEnforcer(lockfile, false)
	filter := NewResponseFilter(enforcer, false)

	hugeNumStr := "1" + strings.Repeat("0", MaxHostIDBytes)
	hugeNum := json.Number(hugeNumStr)

	_, err := filter.Register(hugeNum, "tools/list")
	if err != ErrHostIDTooLarge {
		t.Fatalf("expected ErrHostIDTooLarge for huge json.Number, got %v", err)
	}
}
