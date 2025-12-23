// Package observability provides structured logging and operation tracking for mcptrust.
package observability

import (
	"context"
	"crypto/rand"
	"fmt"
)

type opIDKey struct{}

// WithOpID generates a new operation ID and stores it in the context
// Each CLI invocation should call this once at startup
func WithOpID(ctx context.Context) context.Context {
	return context.WithValue(ctx, opIDKey{}, generateUUID())
}

// OpID retrieves the operation ID from context
// Returns empty string if no op_id was set
func OpID(ctx context.Context) string {
	if id, ok := ctx.Value(opIDKey{}).(string); ok {
		return id
	}
	return ""
}

// generateUUID creates a UUID v4 string
func generateUUID() string {
	var uuid [16]byte
	_, err := rand.Read(uuid[:])
	if err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	// Set version (4) and variant bits
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
