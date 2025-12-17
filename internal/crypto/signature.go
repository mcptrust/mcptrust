package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// signature constants
const (
	SigTypeEd25519  = "ed25519"
	SigTypeSigstore = "sigstore_bundle"
)

// SignatureHeader metadata
type SignatureHeader struct {
	CanonVersion string `json:"canon_version"`
	SigType      string `json:"sig_type,omitempty"`
	BundleEnc    string `json:"bundle_encoding,omitempty"`
}

// SignatureEnvelope header + payload
type SignatureEnvelope struct {
	Header    *SignatureHeader
	Signature []byte // Ed25519 signature bytes
	Bundle    []byte // Sigstore bundle JSON (for sig_type=sigstore_bundle)
}

// WriteSignature creates Ed25519 signature envelope (v2)
func WriteSignature(sig []byte, canonVersion string) []byte {
	header := SignatureHeader{CanonVersion: canonVersion}
	headerBytes, _ := json.Marshal(header)

	sigHex := hex.EncodeToString(sig)
	return []byte(string(headerBytes) + "\n" + sigHex)
}

// WriteSigstoreSignature creates Sigstore bundle envelope (v3)
// canonVersion REQUIRED
func WriteSigstoreSignature(bundleJSON []byte, canonVersion string) ([]byte, error) {
	if canonVersion == "" {
		return nil, fmt.Errorf("canon_version is required for Sigstore signatures")
	}

	header := SignatureHeader{
		CanonVersion: canonVersion,
		SigType:      SigTypeSigstore,
		BundleEnc:    "base64+json",
	}
	headerBytes, _ := json.Marshal(header)

	bundleB64 := base64.StdEncoding.EncodeToString(bundleJSON)
	return []byte(string(headerBytes) + "\n" + bundleB64), nil
}

// ReadSignature parsing envelope (auto-detect format)
func ReadSignature(data []byte) (*SignatureEnvelope, error) {
	content := strings.TrimSpace(string(data))

	// header check
	if strings.HasPrefix(content, "{") {
		// new format (header)
		lines := strings.SplitN(content, "\n", 2)
		if len(lines) != 2 {
			return nil, fmt.Errorf("invalid signature format: expected header and payload")
		}

		var header SignatureHeader
		if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
			return nil, fmt.Errorf("invalid signature header: %w", err)
		}

		payload := strings.TrimSpace(lines[1])

		// check sig_type
		if header.SigType == SigTypeSigstore {
			// Sigstore bundle: base64 decode
			bundle, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return nil, fmt.Errorf("invalid bundle base64: %w", err)
			}
			return &SignatureEnvelope{
				Header: &header,
				Bundle: bundle,
			}, nil
		}

		// Ed25519 signature: hex decode
		sig, err := hex.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("invalid signature hex: %w", err)
		}

		return &SignatureEnvelope{
			Header:    &header,
			Signature: sig,
		}, nil
	}

	// legacy v1: raw hex only
	sig, err := hex.DecodeString(content)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format: %w", err)
	}

	return &SignatureEnvelope{
		Header:    nil, // legacy v1
		Signature: sig,
	}, nil
}

// GetCanonVersion returns canonicalization version
func (e *SignatureEnvelope) GetCanonVersion() string {
	if e.Header == nil {
		return "v1"
	}
	return e.Header.CanonVersion
}

// GetSigType returns type (default ed25519)
func (e *SignatureEnvelope) GetSigType() string {
	if e.Header == nil || e.Header.SigType == "" {
		return SigTypeEd25519
	}
	return e.Header.SigType
}

// IsSigstore returns true if this is a Sigstore bundle
func (e *SignatureEnvelope) IsSigstore() bool {
	return e.GetSigType() == SigTypeSigstore
}

// ValidateForSigstore ensures valid Sigstore envelope
// Error if missing canon_version
func (e *SignatureEnvelope) ValidateForSigstore() error {
	if !e.IsSigstore() {
		return fmt.Errorf("signature is not a Sigstore bundle (sig_type=%s)", e.GetSigType())
	}
	if e.Header == nil {
		return fmt.Errorf("Sigstore signature must have a header with canon_version")
	}
	if e.Header.CanonVersion == "" {
		return fmt.Errorf("canon_version is required for Sigstore signatures")
	}
	if len(e.Bundle) == 0 {
		return fmt.Errorf("Sigstore signature bundle is empty")
	}
	return nil
}
