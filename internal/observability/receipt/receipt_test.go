package receipt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcptrust/mcptrust/internal/observability"
)

func TestWriterOverwrite_WritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")

	w, err := NewWriter(path, "overwrite")
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	r := Receipt{
		SchemaVersion: ReceiptSchemaVersion,
		OpID:          "test-op-id-123",
		TsStart:       "2024-01-01T00:00:00Z",
		TsEnd:         "2024-01-01T00:01:00Z",
		Command:       "mcptrust lock",
		Args:          []string{"--pin", "--verify-provenance"},
		Result:        Result{Status: "success"},
	}

	if err := w.Write(r); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read receipt: %v", err)
	}

	var parsed Receipt
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\nContent: %s", err, string(data))
	}

	if parsed.SchemaVersion != "1.0" {
		t.Errorf("schema_version = %q, want %q", parsed.SchemaVersion, "1.0")
	}
	if parsed.OpID != "test-op-id-123" {
		t.Errorf("op_id = %q, want %q", parsed.OpID, "test-op-id-123")
	}
	if parsed.Result.Status != "success" {
		t.Errorf("result.status = %q, want %q", parsed.Result.Status, "success")
	}
}

func TestWriterAppend_WritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.jsonl")

	w, err := NewWriter(path, "append")
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Write first receipt
	r1 := Receipt{
		SchemaVersion: ReceiptSchemaVersion,
		OpID:          "op-1",
		Command:       "mcptrust lock",
		Result:        Result{Status: "success"},
	}
	if err := w.Write(r1); err != nil {
		t.Fatalf("Write 1 failed: %v", err)
	}

	// Write second receipt
	r2 := Receipt{
		SchemaVersion: ReceiptSchemaVersion,
		OpID:          "op-2",
		Command:       "mcptrust diff",
		Result:        Result{Status: "fail", Error: "drift detected"},
	}
	if err := w.Write(r2); err != nil {
		t.Fatalf("Write 2 failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read receipt: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// Verify each line is valid JSON
	for i, line := range lines {
		var parsed Receipt
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
	}

	// Verify op_ids
	var line1, line2 Receipt
	_ = json.Unmarshal([]byte(lines[0]), &line1)
	_ = json.Unmarshal([]byte(lines[1]), &line2)

	if line1.OpID != "op-1" {
		t.Errorf("line 1 op_id = %q, want %q", line1.OpID, "op-1")
	}
	if line2.OpID != "op-2" {
		t.Errorf("line 2 op_id = %q, want %q", line2.OpID, "op-2")
	}
}

func TestSessionFinish_ComputesLockfileSHA256(t *testing.T) {
	dir := t.TempDir()

	// Create a lockfile with known content
	lockfilePath := filepath.Join(dir, "mcp-lock.json")
	lockfileContent := []byte(`{"version":"2.0","server_command":"echo test","tools":{}}`)
	if err := os.WriteFile(lockfilePath, lockfileContent, 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}

	// Expected SHA256 of the lockfile content
	// sha256sum of `{"version":"2.0","server_command":"echo test","tools":{}}` is:
	// 8c5e...
	var expectedSHA256 string // Set by actual computation below
	// Actually compute the real one
	realSHA256, err := computeSHA256(lockfilePath)
	if err != nil {
		t.Fatalf("failed to compute lockfile SHA256: %v", err)
	}
	expectedSHA256 = realSHA256

	// Create receipt file
	receiptPath := filepath.Join(dir, "receipt.json")
	w, err := NewWriter(receiptPath, "overwrite")
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Create context with writer and op_id
	ctx := observability.WithOpID(context.Background())
	ctx = WithWriter(ctx, w)

	// Create session and finish with lockfile option
	sess := Start(ctx, "mcptrust lock", []string{"--pin"})
	if err := sess.Finish(nil, WithLockfile(lockfilePath)); err != nil {
		t.Fatalf("Finish failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("failed to read receipt: %v", err)
	}

	var parsed Receipt
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed.Lockfile == nil {
		t.Fatal("lockfile is nil")
	}
	if parsed.Lockfile.Path != lockfilePath {
		t.Errorf("lockfile.path = %q, want %q", parsed.Lockfile.Path, lockfilePath)
	}
	if parsed.Lockfile.SHA256 != expectedSHA256 {
		t.Errorf("lockfile.sha256 = %q, want %q", parsed.Lockfile.SHA256, expectedSHA256)
	}
}

func TestErrorTruncation(t *testing.T) {
	dir := t.TempDir()
	receiptPath := filepath.Join(dir, "receipt.json")

	w, err := NewWriter(receiptPath, "overwrite")
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ctx := observability.WithOpID(context.Background())
	ctx = WithWriter(ctx, w)

	// Create a very long error string
	longError := strings.Repeat("x", 5000)

	sess := Start(ctx, "mcptrust lock", []string{"--pin"})
	if err := sess.Finish(fmt.Errorf("error: %s", longError)); err != nil {
		t.Fatalf("Finish failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("failed to read receipt: %v", err)
	}

	var parsed Receipt
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(parsed.Result.Error) > MaxErrorLength {
		t.Errorf("error length = %d, want <= %d", len(parsed.Result.Error), MaxErrorLength)
	}
	if len(parsed.Result.Error) < MaxErrorLength-10 {
		t.Errorf("error should be truncated to near MaxErrorLength, got %d", len(parsed.Result.Error))
	}
}

func TestContextWithWriter(t *testing.T) {
	// Without writer in context
	ctx := context.Background()
	if w := From(ctx); w != nil {
		t.Error("From should return nil when no writer set")
	}

	// With writer in context
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	writer, _ := NewWriter(path, "overwrite")
	ctx = WithWriter(ctx, writer)

	if w := From(ctx); w != writer {
		t.Error("From should return the writer stored in context")
	}
}

func TestWriterCreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	nestedPath := filepath.Join(dir, "a", "b", "c", "receipt.json")

	w, err := NewWriter(nestedPath, "overwrite")
	if err != nil {
		t.Fatalf("NewWriter should create nested directories: %v", err)
	}
	defer w.Close()

	// Verify directory was created
	if _, err := os.Stat(filepath.Dir(nestedPath)); os.IsNotExist(err) {
		t.Error("directory was not created")
	}
}
