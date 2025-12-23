package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcptrust/mcptrust/internal/observability"
)

func TestJSONLLogger_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := &jsonlLogger{
		writer:   &buf,
		minLevel: 0, // debug
	}

	ctx := observability.WithOpID(context.Background())
	logger.Event(ctx, "test.event", map[string]any{"key": "value"})

	output := buf.String()
	if output == "" {
		t.Fatal("expected output, got empty string")
	}

	// Should be valid JSON
	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, output)
	}
}

func TestJSONLLogger_RequiredFields(t *testing.T) {
	var buf bytes.Buffer
	logger := &jsonlLogger{
		writer:   &buf,
		minLevel: 0,
	}

	ctx := observability.WithOpID(context.Background())
	logger.Event(ctx, "test.event", nil)

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	requiredFields := []string{"ts", "level", "event", "component", "op_id", "schema_version"}
	for _, field := range requiredFields {
		if _, ok := entry[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}
}

func TestJSONLLogger_SchemaVersion(t *testing.T) {
	var buf bytes.Buffer
	logger := &jsonlLogger{
		writer:   &buf,
		minLevel: 0,
	}

	ctx := observability.WithOpID(context.Background())
	logger.Event(ctx, "test.event", nil)

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if entry["schema_version"] != "1.0" {
		t.Errorf("schema_version = %v, want 1.0", entry["schema_version"])
	}
}

func TestJSONLLogger_OpIDFromContext(t *testing.T) {
	var buf bytes.Buffer
	logger := &jsonlLogger{
		writer:   &buf,
		minLevel: 0,
	}

	ctx := observability.WithOpID(context.Background())
	expectedOpID := observability.OpID(ctx)
	logger.Event(ctx, "test.event", nil)

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if entry["op_id"] != expectedOpID {
		t.Errorf("op_id = %v, want %v", entry["op_id"], expectedOpID)
	}
}

func TestJSONLLogger_LevelFiltering(t *testing.T) {
	tests := []struct {
		minLevel int
		logLevel string
		method   func(*jsonlLogger)
		want     bool
	}{
		{levelPriority(LevelInfo), LevelDebug, func(l *jsonlLogger) { l.Debug("c", "m") }, false},
		{levelPriority(LevelInfo), LevelInfo, func(l *jsonlLogger) { l.Info("c", "m") }, true},
		{levelPriority(LevelWarn), LevelInfo, func(l *jsonlLogger) { l.Info("c", "m") }, false},
		{levelPriority(LevelError), LevelWarn, func(l *jsonlLogger) { l.Warn("c", "m") }, false},
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		logger := &jsonlLogger{
			writer:   &buf,
			minLevel: tt.minLevel,
		}
		tt.method(logger)

		got := buf.Len() > 0
		if got != tt.want {
			t.Errorf("minLevel=%d, logLevel=%s: got output=%v, want %v",
				tt.minLevel, tt.logLevel, got, tt.want)
		}
	}
}

func TestJSONLLogger_MultipleLines(t *testing.T) {
	var buf bytes.Buffer
	logger := &jsonlLogger{
		writer:   &buf,
		minLevel: 0,
	}

	ctx := observability.WithOpID(context.Background())
	logger.Event(ctx, "first.event", nil)
	logger.Event(ctx, "second.event", nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}

	// Each line should be valid JSON
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
	}
}

func TestJSONLLogger_Fields(t *testing.T) {
	var buf bytes.Buffer
	logger := &jsonlLogger{
		writer:   &buf,
		minLevel: 0,
	}

	ctx := observability.WithOpID(context.Background())
	logger.Event(ctx, "test.event", map[string]any{
		"duration_ms": 123,
		"result":      "success",
	})

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	fields, ok := entry["fields"].(map[string]any)
	if !ok {
		t.Fatal("fields is not a map")
	}

	if fields["duration_ms"] != float64(123) { // JSON numbers are float64
		t.Errorf("duration_ms = %v, want 123", fields["duration_ms"])
	}
	if fields["result"] != "success" {
		t.Errorf("result = %v, want success", fields["result"])
	}
}

func TestNewLogger_Pretty(t *testing.T) {
	logger, err := NewLogger(Config{Format: "pretty"})
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer logger.Close()

	// Pretty logger should be no-op
	if _, ok := logger.(*noopLogger); !ok {
		t.Error("pretty format should return noopLogger")
	}
}

func TestNewLogger_JSONL(t *testing.T) {
	logger, err := NewLogger(Config{Format: "jsonl"})
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer logger.Close()

	// JSONL logger
	if _, ok := logger.(*jsonlLogger); !ok {
		t.Error("jsonl format should return jsonlLogger")
	}
}

func TestNewLogger_FileOutput(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")

	logger, err := NewLogger(Config{
		Format: "jsonl",
		Output: logFile,
	})
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	ctx := observability.WithOpID(context.Background())
	logger.Event(ctx, "test.event", nil)
	logger.Close()

	// Verify file was written
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("log file content is not valid JSON: %v", err)
	}
}

func TestFromContext_NoLogger(t *testing.T) {
	ctx := context.Background()
	logger := From(ctx)

	// Should return no-op logger, not nil
	if logger == nil {
		t.Fatal("From should never return nil")
	}

	// Should not panic when called
	logger.Debug("test", "msg")
	logger.Info("test", "msg")
	logger.Warn("test", "msg")
	logger.Error("test", "msg")
	logger.Event(ctx, "test.event", nil)
}

func TestFromContext_WithLogger(t *testing.T) {
	var buf bytes.Buffer
	original := &jsonlLogger{
		writer:   &buf,
		minLevel: 0,
	}

	ctx := WithLogger(context.Background(), original)
	retrieved := From(ctx)

	if retrieved != original {
		t.Error("From should return the logger stored in context")
	}
}
