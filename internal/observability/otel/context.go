package otel

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

type handleKey struct{}

// Handle wraps tracer and shutdown
type Handle struct {
	Tracer   trace.Tracer
	Shutdown func(context.Context) error
}

// WithHandle stores the OTel Handle in context.
func WithHandle(ctx context.Context, h *Handle) context.Context {
	return context.WithValue(ctx, handleKey{}, h)
}

// From retrieves the OTel Handle from context.
// Returns nil if OTel is not enabled.
func From(ctx context.Context) *Handle {
	h, _ := ctx.Value(handleKey{}).(*Handle)
	return h
}
