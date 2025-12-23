package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Resource limits - protects against malicious servers and OOM attacks
const (
	// MaxNDJSONLineSize - 10MB max line, returns ErrLineTooLong if exceeded
	MaxNDJSONLineSize = 10 * 1024 * 1024

	// MaxPendingRequests - prevents request flooding OOM
	// Returns ErrPendingMapFull -> JSON-RPC -32002, request NOT forwarded (fail-closed)
	MaxPendingRequests = 1024

	// MaxRecentUsedIDs - duplicate detection map cap, pruned when exceeded
	MaxRecentUsedIDs = 4096

	// UsedIDTTL - how long to track used IDs for SEC-04 duplicate detection
	UsedIDTTL = 60 * time.Second

	// MaxIDLiteralBytes - IDs over this skip numeric parsing (DoS prevention)
	// Fail-closed: long IDs become s:<val> keys, can't match n:<val>
	MaxIDLiteralBytes = 256

	// MaxHostIDBytes - SEC-01: reject huge IDs before storing (OOM prevention)
	MaxHostIDBytes = 256
)

var ErrLineTooLong = errors.New("NDJSON line exceeds maximum size")

var ErrPendingMapFull = errors.New("pending request map at capacity")

var ErrHostIDTooLarge = errors.New("host ID exceeds maximum size")

var ErrHostIDInvalidType = errors.New("host ID must be a JSON-RPC scalar (string, number, or null)")

func ValidateHostID(id interface{}) error {
	switch v := id.(type) {
	case nil:
		return nil
	case string:
		if len(v) > MaxHostIDBytes {
			return ErrHostIDTooLarge
		}
		return nil
	case json.Number:
		if len(string(v)) > MaxHostIDBytes {
			return ErrHostIDTooLarge
		}
		return nil
	case float64:
		return nil
	case int:
		return nil
	case int64:
		return nil
	case map[string]interface{}:
		return ErrHostIDInvalidType
	case []interface{}:
		return ErrHostIDInvalidType
	default:
		return ErrHostIDInvalidType
	}
}

// LimitedLineReader bounds line reading to prevent OOM
type LimitedLineReader struct {
	reader  *bufio.Reader
	maxSize int
	buf     []byte
}

func NewLimitedLineReader(r io.Reader, maxSize int) *LimitedLineReader {
	return &LimitedLineReader{
		reader:  bufio.NewReaderSize(r, 64*1024), // 64KB buffer for efficiency
		maxSize: maxSize,
		buf:     make([]byte, 0, 4096), // Start small, grow as needed
	}
}

func (l *LimitedLineReader) ReadLine() ([]byte, error) {
	l.buf = l.buf[:0]

	for {
		if len(l.buf) >= l.maxSize {
			for {
				b, err := l.reader.ReadByte()
				if err != nil || b == '\n' {
					break
				}
			}
			return nil, ErrLineTooLong
		}

		b, err := l.reader.ReadByte()
		if err != nil {
			if err == io.EOF && len(l.buf) > 0 {
				return l.buf, nil
			}
			return nil, err
		}

		if b == '\n' {
			result := l.buf
			if len(result) > 0 && result[len(result)-1] == '\r' {
				result = result[:len(result)-1]
			}
			return result, nil
		}

		l.buf = append(l.buf, b)
	}
}

func (l *LimitedLineReader) ReadLineJSON() ([]byte, error) {
	line, err := l.ReadLine()
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(line))
	copy(result, line)
	return result, nil
}

func ScanLinesWithLimit(maxSize int) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}

		if len(data) > maxSize {
			if i := bytes.IndexByte(data, '\n'); i >= 0 {
				return i + 1, nil, ErrLineTooLong
			}
			return 0, nil, ErrLineTooLong
		}

		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line := data[0:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			return i + 1, line, nil
		}

		if atEOF {
			return len(data), data, nil
		}

		return 0, nil, nil
	}
}
