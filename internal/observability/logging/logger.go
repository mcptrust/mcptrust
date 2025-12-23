package logging

import (
	"context"
	"io"
	"os"
)

type Logger interface {
	Debug(component, msg string, fields ...any)
	Info(component, msg string, fields ...any)
	Warn(component, msg string, fields ...any)
	Error(component, msg string, fields ...any)
	Event(ctx context.Context, event string, fields map[string]any)
	Close() error
}

type loggerKey struct{}

func WithLogger(ctx context.Context, l Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

func From(ctx context.Context) Logger {
	if l, ok := ctx.Value(loggerKey{}).(Logger); ok {
		return l
	}
	return &noopLogger{}
}

func NewLogger(cfg Config) (Logger, error) {
	var w io.Writer
	var closer io.Closer

	if cfg.Output == "" || cfg.Output == "stderr" {
		w = os.Stderr
	} else {
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		w = f
		closer = f
	}

	if cfg.Format == "jsonl" {
		return &jsonlLogger{
			writer:   w,
			closer:   closer,
			minLevel: levelPriority(cfg.Level),
		}, nil
	}

	return &noopLogger{closer: closer}, nil
}

type noopLogger struct {
	closer io.Closer
}

func (n *noopLogger) Debug(component, msg string, fields ...any) {}
func (n *noopLogger) Info(component, msg string, fields ...any)  {}
func (n *noopLogger) Warn(component, msg string, fields ...any)  {}
func (n *noopLogger) Error(component, msg string, fields ...any) {}
func (n *noopLogger) Event(ctx context.Context, event string, fields map[string]any) {
}
func (n *noopLogger) Close() error {
	if n.closer != nil {
		return n.closer.Close()
	}
	return nil
}
