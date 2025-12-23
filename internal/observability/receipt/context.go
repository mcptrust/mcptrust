package receipt

import "context"

type writerKey struct{}

// WithWriter stores a receipt writer in the context.
func WithWriter(ctx context.Context, w Writer) context.Context {
	return context.WithValue(ctx, writerKey{}, w)
}

// From retrieves the receipt writer from context.
// Returns nil if no writer was set.
func From(ctx context.Context) Writer {
	if w, ok := ctx.Value(writerKey{}).(Writer); ok {
		return w
	}
	return nil
}
