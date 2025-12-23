package proxy

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

func TestLimitedLineReader_NormalLines(t *testing.T) {
	input := "line1\nline2\nline3\n"
	r := NewLimitedLineReader(strings.NewReader(input), 1024)

	expected := []string{"line1", "line2", "line3"}
	for i, want := range expected {
		line, err := r.ReadLine()
		if err != nil {
			t.Fatalf("ReadLine %d: unexpected error: %v", i, err)
		}
		if string(line) != want {
			t.Errorf("ReadLine %d: got %q, want %q", i, string(line), want)
		}
	}

	// Should return EOF
	_, err := r.ReadLine()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestLimitedLineReader_CRLF(t *testing.T) {
	input := "line1\r\nline2\r\n"
	r := NewLimitedLineReader(strings.NewReader(input), 1024)

	line, err := r.ReadLine()
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if string(line) != "line1" {
		t.Errorf("got %q, want %q", string(line), "line1")
	}

	line, err = r.ReadLine()
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if string(line) != "line2" {
		t.Errorf("got %q, want %q", string(line), "line2")
	}
}

func TestLimitedLineReader_ExactLimit(t *testing.T) {
	// Create a line exactly at the limit
	maxSize := 100
	lineContent := strings.Repeat("x", maxSize-1) // -1 because we add newline
	input := lineContent + "\n"

	r := NewLimitedLineReader(strings.NewReader(input), maxSize)
	line, err := r.ReadLine()
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if string(line) != lineContent {
		t.Errorf("line length = %d, want %d", len(line), len(lineContent))
	}
}

func TestLimitedLineReader_OverLimit(t *testing.T) {
	// Create a line that exceeds the limit
	maxSize := 100
	lineContent := strings.Repeat("x", maxSize+50) + "\n"

	r := NewLimitedLineReader(strings.NewReader(lineContent), maxSize)
	_, err := r.ReadLine()

	if !errors.Is(err, ErrLineTooLong) {
		t.Errorf("expected ErrLineTooLong, got %v", err)
	}
}

func TestLimitedLineReader_OverLimitNoOOM(t *testing.T) {
	// Simulate a very large line without actually allocating it
	// We use a reader that returns 'x' bytes until a limit, then newline
	maxSize := 1024
	hugeSize := 10 * maxSize // 10x the limit

	r := NewLimitedLineReader(&endlessReader{remaining: hugeSize}, maxSize)
	_, err := r.ReadLine()

	if !errors.Is(err, ErrLineTooLong) {
		t.Errorf("expected ErrLineTooLong, got %v", err)
	}

	// The key check: we should not have allocated hugeSize bytes
	// This is implicit - if we did, the test would be slow/OOM
}

// endlessReader returns 'x' bytes until remaining hits 0, then '\n'
type endlessReader struct {
	remaining int
}

func (r *endlessReader) Read(p []byte) (n int, err error) {
	if r.remaining <= 0 {
		if len(p) > 0 {
			p[0] = '\n'
			return 1, nil
		}
		return 0, io.EOF
	}

	toRead := len(p)
	if toRead > r.remaining {
		toRead = r.remaining
	}

	for i := 0; i < toRead; i++ {
		p[i] = 'x'
	}
	r.remaining -= toRead
	return toRead, nil
}

func TestLimitedLineReader_MultipleReads(t *testing.T) {
	// Ensure buffer reuse works correctly
	input := "short\n" + strings.Repeat("m", 50) + "\nshort2\n"
	r := NewLimitedLineReader(strings.NewReader(input), 100)

	line1, _ := r.ReadLine()
	if string(line1) != "short" {
		t.Errorf("line1 = %q", string(line1))
	}

	line2, _ := r.ReadLine()
	if len(line2) != 50 {
		t.Errorf("line2 length = %d, want 50", len(line2))
	}

	line3, _ := r.ReadLine()
	if string(line3) != "short2" {
		t.Errorf("line3 = %q", string(line3))
	}
}

func TestLimitedLineReader_ReadLineJSON(t *testing.T) {
	input := `{"id":1,"method":"test"}` + "\n"
	r := NewLimitedLineReader(strings.NewReader(input), 1024)

	line, err := r.ReadLineJSON()
	if err != nil {
		t.Fatalf("ReadLineJSON: %v", err)
	}

	// Verify it's valid JSON (parseable)
	expected := `{"id":1,"method":"test"}`
	if string(line) != expected {
		t.Errorf("got %q, want %q", string(line), expected)
	}
}

func TestLimitedLineReader_FinalLineNoNewline(t *testing.T) {
	input := "line without newline"
	r := NewLimitedLineReader(strings.NewReader(input), 1024)

	line, err := r.ReadLine()
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if string(line) != input {
		t.Errorf("got %q, want %q", string(line), input)
	}
}

func TestScanLinesWithLimit_Normal(t *testing.T) {
	input := "line1\nline2\n"
	splitFunc := ScanLinesWithLimit(1024)

	advance, token, err := splitFunc([]byte(input), false)
	if err != nil {
		t.Fatalf("split error: %v", err)
	}
	if advance != 6 { // "line1\n"
		t.Errorf("advance = %d, want 6", advance)
	}
	if string(token) != "line1" {
		t.Errorf("token = %q, want %q", string(token), "line1")
	}
}

func TestScanLinesWithLimit_OverLimit(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 150)
	data = append(data, '\n')

	splitFunc := ScanLinesWithLimit(100)
	_, _, err := splitFunc(data, false)

	if !errors.Is(err, ErrLineTooLong) {
		t.Errorf("expected ErrLineTooLong, got %v", err)
	}
}

// TestPendingMapFull_ListRequestDeniedNotForwarded verifies SEC-04 fail-closed:
// When pending map is full, list requests are denied with error (not forwarded).
func TestPendingMapFull_ListRequestDeniedNotForwarded(t *testing.T) {
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

	// Fill up the pending map to MaxPendingRequests
	for i := 0; i < MaxPendingRequests; i++ {
		_, err := filter.Register(i, "tools/list")
		if err != nil {
			t.Fatalf("Register(%d) should succeed: %v", i, err)
		}
	}

	if filter.PendingCount() != MaxPendingRequests {
		t.Fatalf("pending count = %d, want %d", filter.PendingCount(), MaxPendingRequests)
	}

	// Next registration should FAIL
	_, err = filter.Register(MaxPendingRequests, "tools/list")
	if err != ErrPendingMapFull {
		t.Errorf("Register when full should return ErrPendingMapFull, got %v", err)
	}
}

// TestPendingMapFull_DoesNotBypassEnforcement verifies SEC-04:
// A malicious actor cannot DoS the pending map to bypass filtering.
// When the map is full, the request is DENIED (fail-closed), not forwarded unfiltered.
func TestPendingMapFull_DoesNotBypassEnforcement(t *testing.T) {
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

	// Fill up to capacity
	for i := 0; i < MaxPendingRequests; i++ {
		_, _ = filter.Register(i, "tools/list")
	}

	// Verify at capacity
	if filter.PendingCount() != MaxPendingRequests {
		t.Fatalf("pending count = %d, want %d", filter.PendingCount(), MaxPendingRequests)
	}

	// Attempt to register when full - should return error
	_, err = filter.Register("bypass-attempt", "tools/list")
	if err == nil {
		t.Error("FAIL-OPEN VULNERABILITY: Register succeeded when at capacity!")
		t.Error("This would allow bypass - list endpoint responses would flow unfiltered")
	}

	// Verify that error is returned for caller to deny the request
	if err != ErrPendingMapFull {
		t.Errorf("expected ErrPendingMapFull, got %v", err)
	}

	// Simulate what proxy.go should do: caller sees error, sends MCPTRUST_OVERLOADED
	// and does NOT forward the request to the server
	errorResp := OverloadedError("bypass-attempt")
	if errorResp == nil {
		t.Error("OverloadedError should return a valid response")
	}

	errField, _ := errorResp["error"].(map[string]interface{})
	if errField == nil {
		t.Error("OverloadedError should have error field")
	} else if errField["code"] != MCPTrustOverloadedCode {
		t.Errorf("error code = %v, want %d", errField["code"], MCPTrustOverloadedCode)
	}
}

// TestOverloadedError_CorrectFormat verifies the error response format
func TestOverloadedError_CorrectFormat(t *testing.T) {
	resp := OverloadedError(123)

	if resp["jsonrpc"] != "2.0" {
		t.Error("expected jsonrpc: 2.0")
	}
	if resp["id"] != 123 {
		t.Errorf("expected id: 123, got %v", resp["id"])
	}

	errField, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("error field should be a map")
	}

	if errField["code"] != MCPTrustOverloadedCode {
		t.Errorf("error.code = %v, want %d", errField["code"], MCPTrustOverloadedCode)
	}

	msg, _ := errField["message"].(string)
	if msg == "" {
		t.Error("error.message should not be empty")
	}
}

// TestLogOversizeNDJSON_Format verifies the stderr log message format for oversize NDJSON lines.
// This test captures stderr and validates the operator-visible log message.
func TestLogOversizeNDJSON_Format(t *testing.T) {
	// Save original stderr
	oldStderr := os.Stderr

	// Create a pipe to capture stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	// Call the log function
	logOversizeNDJSON("host->proxy", "request")

	// Restore stderr and close writer
	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Verify the format is stable and grep-able
	expected := "mcptrust: dropped_oversize_ndjson_line"
	if !strings.Contains(output, expected) {
		t.Errorf("log output should contain %q, got %q", expected, output)
	}
	if !strings.Contains(output, "direction=host->proxy") {
		t.Errorf("log output should contain direction=host->proxy, got %q", output)
	}
	if !strings.Contains(output, "limit_bytes=") {
		t.Errorf("log output should contain limit_bytes=, got %q", output)
	}
	if !strings.Contains(output, "phase=request") {
		t.Errorf("log output should contain phase=request, got %q", output)
	}
}
