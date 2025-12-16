package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// SignatureHeader metadata
type SignatureHeader struct {
	CanonVersion string `json:"canon_version"`
}

// SignatureEnvelope header + bytes
type SignatureEnvelope struct {
	Header    *SignatureHeader
	Signature []byte
}

// WriteSignature adds header
func WriteSignature(sig []byte, canonVersion string) []byte {
	header := SignatureHeader{CanonVersion: canonVersion}
	headerBytes, _ := json.Marshal(header)

	sigHex := hex.EncodeToString(sig)
	return []byte(string(headerBytes) + "\n" + sigHex)
}

// ReadSignature parses envelope
func ReadSignature(data []byte) (*SignatureEnvelope, error) {
	content := strings.TrimSpace(string(data))

	// header check
	if strings.HasPrefix(content, "{") {
		// new format
		lines := strings.SplitN(content, "\n", 2)
		if len(lines) != 2 {
			return nil, fmt.Errorf("invalid signature format: expected header and signature")
		}

		var header SignatureHeader
		if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
			return nil, fmt.Errorf("invalid signature header: %w", err)
		}

		sig, err := hex.DecodeString(strings.TrimSpace(lines[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid signature hex: %w", err)
		}

		return &SignatureEnvelope{
			Header:    &header,
			Signature: sig,
		}, nil
	}

	// legacy v1
	sig, err := hex.DecodeString(content)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format: %w", err)
	}

	return &SignatureEnvelope{
		Header:    nil, // nil header means legacy v1
		Signature: sig,
	}, nil
}

// GetCanonVersion
func (e *SignatureEnvelope) GetCanonVersion() string {
	if e.Header == nil {
		return "v1"
	}
	return e.Header.CanonVersion
}
