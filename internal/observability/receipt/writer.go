package receipt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Writer for receipts
type Writer interface {
	Write(r Receipt) error
	Close() error
}

// Mode write strategy
type Mode string

const (
	// ModeOverwrite truncates the file and writes a single JSON object.
	ModeOverwrite Mode = "overwrite"
	// ModeAppend appends JSONL (one JSON object per line).
	ModeAppend Mode = "append"
)

// fileWriter implementation
type fileWriter struct {
	mu   sync.Mutex
	file *os.File
	mode Mode
}

// NewWriter factory
func NewWriter(path string, mode string) (Writer, error) {
	m := Mode(mode)
	if m != ModeOverwrite && m != ModeAppend {
		m = ModeOverwrite // default
	}

	// Create directories if needed
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for receipt: %w", err)
		}
	}

	// Open file based on mode
	var flag int
	if m == ModeAppend {
		flag = os.O_CREATE | os.O_APPEND | os.O_WRONLY
	} else {
		flag = os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	}

	f, err := os.OpenFile(path, flag, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open receipt file: %w", err)
	}

	return &fileWriter{
		file: f,
		mode: m,
	}, nil
}

// Write receipt
func (w *fileWriter) Write(r Receipt) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal receipt: %w", err)
	}

	if w.mode == ModeAppend {
		// JSONL: append newline
		data = append(data, '\n')
	}

	if _, err := w.file.Write(data); err != nil {
		return fmt.Errorf("failed to write receipt: %w", err)
	}

	return nil
}

// Close file
func (w *fileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
