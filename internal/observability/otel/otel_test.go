package otel

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "disabled is always valid",
			cfg:     Config{Enabled: false, Protocol: "invalid", SampleRatio: -1},
			wantErr: false,
		},
		{
			name:    "valid otlphttp",
			cfg:     Config{Enabled: true, Protocol: ProtocolHTTP, SampleRatio: 0.5},
			wantErr: false,
		},
		{
			name:    "valid otlpgrpc",
			cfg:     Config{Enabled: true, Protocol: ProtocolGRPC, SampleRatio: 1.0},
			wantErr: false,
		},
		{
			name:    "invalid protocol",
			cfg:     Config{Enabled: true, Protocol: "invalid", SampleRatio: 1.0},
			wantErr: true,
		},
		{
			name:    "sample ratio below 0",
			cfg:     Config{Enabled: true, Protocol: ProtocolHTTP, SampleRatio: -0.1},
			wantErr: true,
		},
		{
			name:    "sample ratio above 1",
			cfg:     Config{Enabled: true, Protocol: ProtocolHTTP, SampleRatio: 1.5},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSpanCreatedWithAttributes(t *testing.T) {
	// Create in-memory span recorder
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	h := InitWithProvider(tp)
	ctx := context.Background()

	// Start and end a span
	ctx, span := h.Tracer.Start(ctx, "mcptrust.test",
		trace.WithAttributes(
			attribute.String("mcptrust.command", "test"),
			attribute.String("mcptrust.op_id", "abc-123"),
		),
	)
	span.SetStatus(codes.Ok, "success")
	span.End()

	// Force flush
	_ = tp.ForceFlush(ctx)

	// Check recorded spans
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	s := spans[0]
	if s.Name() != "mcptrust.test" {
		t.Errorf("span name = %q, want %q", s.Name(), "mcptrust.test")
	}

	// Check attributes
	attrs := s.Attributes()
	var foundCommand, foundOpID bool
	for _, attr := range attrs {
		switch string(attr.Key) {
		case "mcptrust.command":
			foundCommand = true
			if attr.Value.AsString() != "test" {
				t.Errorf("mcptrust.command = %q, want %q", attr.Value.AsString(), "test")
			}
		case "mcptrust.op_id":
			foundOpID = true
		}
	}
	if !foundCommand {
		t.Error("missing attribute: mcptrust.command")
	}
	if !foundOpID {
		t.Error("missing attribute: mcptrust.op_id")
	}
}

func TestSpanRecordsError(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	h := InitWithProvider(tp)
	ctx := context.Background()

	// Start span, record error, end
	_, span := h.Tracer.Start(ctx, "mcptrust.failing")
	testErr := errors.New("something went wrong")
	span.RecordError(testErr)
	span.SetStatus(codes.Error, "failed")
	span.End()

	_ = tp.ForceFlush(ctx)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	s := spans[0]
	if s.Status().Code != codes.Error {
		t.Errorf("span status = %v, want Error", s.Status().Code)
	}

	// Check that error was recorded as an event
	events := s.Events()
	foundError := false
	for _, e := range events {
		if e.Name == "exception" {
			foundError = true
		}
	}
	if !foundError {
		t.Error("expected error event to be recorded")
	}
}

func TestContextRoundtrip(t *testing.T) {
	// Without handle
	ctx := context.Background()
	if h := From(ctx); h != nil {
		t.Error("expected nil handle from empty context")
	}

	// With handle
	handle := &Handle{}
	ctx = WithHandle(ctx, handle)
	if got := From(ctx); got != handle {
		t.Error("expected to retrieve the same handle from context")
	}
}
