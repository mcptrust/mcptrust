package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Bridge handles NDJSON I/O between host and server with bounded line sizes
type Bridge struct {
	hostIn    *LimitedLineReader
	hostOut   io.Writer
	serverIn  io.Writer
	serverOut *LimitedLineReader
	writeMu   sync.Mutex
}

// NewBridge creates a new bridge for host<->server communication
// Lines are limited to MaxNDJSONLineSize to prevent memory exhaustion
func NewBridge(hostIn io.Reader, hostOut io.Writer, serverIn io.Writer, serverOut io.Reader) *Bridge {
	return &Bridge{
		hostIn:    NewLimitedLineReader(hostIn, MaxNDJSONLineSize),
		hostOut:   hostOut,
		serverIn:  serverIn,
		serverOut: NewLimitedLineReader(serverOut, MaxNDJSONLineSize),
	}
}

// ReadRequest reads a JSON-RPC request from host stdin
// Returns ErrLineTooLong if the request exceeds MaxNDJSONLineSize
// Uses json.Decoder.UseNumber() to preserve large integer IDs exactly
func (b *Bridge) ReadRequest() (map[string]interface{}, error) {
	line, err := b.hostIn.ReadLineJSON()
	if err != nil {
		return nil, err
	}
	return decodeJSONWithNumber(line, "host")
}

// WriteResponse writes a JSON-RPC response to host stdout (thread-safe)
func (b *Bridge) WriteResponse(resp map[string]interface{}) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	_, err = fmt.Fprintln(b.hostOut, string(data))
	return err
}

// ForwardToServer writes a JSON-RPC request to server stdin
func (b *Bridge) ForwardToServer(req map[string]interface{}) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	_, err = fmt.Fprintln(b.serverIn, string(data))
	return err
}

// ReadServerResponse reads a JSON-RPC response from server stdout
// Returns ErrLineTooLong if the response exceeds MaxNDJSONLineSize
// Uses json.Decoder.UseNumber() to preserve large integer IDs exactly
func (b *Bridge) ReadServerResponse() (map[string]interface{}, error) {
	line, err := b.serverOut.ReadLineJSON()
	if err != nil {
		return nil, err
	}
	return decodeJSONWithNumber(line, "server")
}

// decodeJSONWithNumber decodes JSON using json.Decoder.UseNumber()
// This preserves large integer IDs (>2^53) as json.Number instead of
// converting them to float64, which would lose precision
func decodeJSONWithNumber(data []byte, source string) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var obj map[string]interface{}
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid JSON from %s: %w", source, err)
	}

	return obj, nil
}
