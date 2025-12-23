package receipt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"time"

	"github.com/mcptrust/mcptrust/internal/observability"
)

// MaxErrorLength is the maximum length for error strings in receipts.
const MaxErrorLength = 2048

// Session tracks command execution
type Session struct {
	ctx     context.Context
	start   time.Time
	command string
	args    []string
}

// Start session
func Start(ctx context.Context, cmd string, args []string) *Session {
	return &Session{
		ctx:     ctx,
		start:   time.Now(),
		command: cmd,
		args:    args,
	}
}

// Option configures receipt
type Option func(*Receipt)

// WithLockfile option
func WithLockfile(path string) Option {
	return func(r *Receipt) {
		if path == "" {
			return
		}
		ref := &LockfileRef{Path: path}
		// Compute SHA256 if file exists
		if hash, err := computeSHA256(path); err == nil {
			ref.SHA256 = hash
		}
		r.Lockfile = ref
	}
}

// WithArtifact option
func WithArtifact(a ArtifactSummary) Option {
	return func(r *Receipt) {
		r.Artifact = &a
	}
}

// WithDrift option
func WithDrift(critical, benign int, summary string) Option {
	return func(r *Receipt) {
		r.Drift = &DriftSummary{
			Critical: critical,
			Benign:   benign,
			Summary:  summary,
		}
	}
}

// WithPolicy option
func WithPolicy(preset, status string, hits []RuleHit) Option {
	return func(r *Receipt) {
		r.Policy = &PolicySummary{
			Preset:   preset,
			Status:   status,
			RulesHit: hits,
		}
	}
}

// Finish and write receipt
func (s *Session) Finish(err error, opts ...Option) error {
	w := From(s.ctx)
	if w == nil {
		// No writer configured, receipts disabled
		return nil
	}

	// SEC-06: Redact sensitive CLI arguments before storing
	redactedArgs, wasRedacted := RedactArgs(s.args)

	r := Receipt{
		SchemaVersion: ReceiptSchemaVersion,
		OpID:          observability.OpID(s.ctx),
		TsStart:       s.start.Format(time.RFC3339Nano),
		TsEnd:         time.Now().Format(time.RFC3339Nano),
		Command:       s.command,
		Args:          redactedArgs,
		ArgsRedacted:  wasRedacted,
	}

	// Set result
	if err != nil {
		r.Result = Result{
			Status: "fail",
			Error:  truncateError(err.Error()),
		}
	} else {
		r.Result = Result{
			Status: "success",
		}
	}

	// Apply options
	for _, opt := range opts {
		opt(&r)
	}

	return w.Write(r)
}

// computeSHA256 helper
func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// truncateError helper
func truncateError(s string) string {
	if len(s) <= MaxErrorLength {
		return s
	}
	return s[:MaxErrorLength-3] + "..."
}
