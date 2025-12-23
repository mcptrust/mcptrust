package logging

import (
	"context"
	"encoding/json"
	"io"
	"runtime"
	"sync"
	"time"

	"github.com/mcptrust/mcptrust/internal/observability"
	"github.com/mcptrust/mcptrust/internal/version"
)

const SchemaVersion = "1.0"

type jsonlLogger struct {
	writer   io.Writer
	closer   io.Closer
	minLevel int
	mu       sync.Mutex
}

type logEntry struct {
	Timestamp       string         `json:"ts"`
	Level           string         `json:"level"`
	Event           string         `json:"event,omitempty"`
	Component       string         `json:"component"`
	OpID            string         `json:"op_id"`
	SchemaVersion   string         `json:"schema_version"`
	MCPTrustVersion string         `json:"mcptrust_version,omitempty"`
	GoVersion       string         `json:"go_version,omitempty"`
	Message         string         `json:"msg,omitempty"`
	Fields          map[string]any `json:"fields,omitempty"`
}

func (j *jsonlLogger) log(level, component, msg string, fields ...any) {
	if levelPriority(level) < j.minLevel {
		return
	}

	entry := logEntry{
		Timestamp:       time.Now().Format(time.RFC3339Nano),
		Level:           level,
		Component:       component,
		OpID:            "", // No context available in simple log methods
		SchemaVersion:   SchemaVersion,
		MCPTrustVersion: version.BuildVersion(),
		GoVersion:       runtime.Version(),
		Message:         msg,
	}

	if len(fields) > 0 {
		entry.Fields = make(map[string]any)
		for i := 0; i+1 < len(fields); i += 2 {
			if key, ok := fields[i].(string); ok {
				entry.Fields[key] = fields[i+1]
			}
		}
	}

	j.writeEntry(entry)
}

func (j *jsonlLogger) Event(ctx context.Context, event string, fields map[string]any) {
	entry := logEntry{
		Timestamp:       time.Now().Format(time.RFC3339Nano),
		Level:           LevelInfo,
		Event:           "mcptrust." + event, // Prefix for SIEM namespacing
		Component:       "cli",
		OpID:            observability.OpID(ctx),
		SchemaVersion:   SchemaVersion,
		MCPTrustVersion: version.BuildVersion(),
		GoVersion:       runtime.Version(),
		Fields:          fields,
	}
	j.writeEntry(entry)
}

func (j *jsonlLogger) writeEntry(entry logEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return // silently skip malformed entries
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if _, err := j.writer.Write(data); err != nil {
		return // best effort
	}
	_, _ = j.writer.Write([]byte("\n")) // best effort, ignore second write error if first succeeded or checked
}

func (j *jsonlLogger) Debug(component, msg string, fields ...any) {
	j.log(LevelDebug, component, msg, fields...)
}

func (j *jsonlLogger) Info(component, msg string, fields ...any) {
	j.log(LevelInfo, component, msg, fields...)
}

func (j *jsonlLogger) Warn(component, msg string, fields ...any) {
	j.log(LevelWarn, component, msg, fields...)
}

func (j *jsonlLogger) Error(component, msg string, fields ...any) {
	j.log(LevelError, component, msg, fields...)
}

func (j *jsonlLogger) Close() error {
	if j.closer != nil {
		return j.closer.Close()
	}
	return nil
}
