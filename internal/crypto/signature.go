package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	SigTypeEd25519  = "ed25519"
	SigTypeSigstore = "sigstore_bundle"
)

type SignatureHeader struct {
	CanonVersion string `json:"canon_version"`
	SigType      string `json:"sig_type,omitempty"`
	BundleEnc    string `json:"bundle_encoding,omitempty"`
}

type SignatureEnvelope struct {
	Header    *SignatureHeader
	Signature []byte
	Bundle    []byte
}

func WriteSignature(sig []byte, canonVersion string) []byte {
	header := SignatureHeader{CanonVersion: canonVersion}
	headerBytes, _ := json.Marshal(header)

	sigHex := hex.EncodeToString(sig)
	return []byte(string(headerBytes) + "\n" + sigHex)
}

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

func ReadSignature(data []byte) (*SignatureEnvelope, error) {
	content := strings.TrimSpace(string(data))

	if strings.HasPrefix(content, "{") {
		lines := strings.SplitN(content, "\n", 2)
		if len(lines) != 2 {
			return nil, fmt.Errorf("invalid signature format: expected header and payload")
		}

		var header SignatureHeader
		if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
			return nil, fmt.Errorf("invalid signature header: %w", err)
		}

		payload := strings.TrimSpace(lines[1])

		if header.SigType == SigTypeSigstore {
			bundle, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return nil, fmt.Errorf("invalid bundle base64: %w", err)
			}
			return &SignatureEnvelope{
				Header: &header,
				Bundle: bundle,
			}, nil
		}

		sig, err := hex.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("invalid signature hex: %w", err)
		}

		return &SignatureEnvelope{
			Header:    &header,
			Signature: sig,
		}, nil
	}

	sig, err := hex.DecodeString(content)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format: %w", err)
	}

	return &SignatureEnvelope{
		Header:    nil,
		Signature: sig,
	}, nil
}

func (e *SignatureEnvelope) GetCanonVersion() string {
	if e.Header == nil {
		return "v1"
	}
	return e.Header.CanonVersion
}

func (e *SignatureEnvelope) GetSigType() string {
	if e.Header == nil || e.Header.SigType == "" {
		return SigTypeEd25519
	}
	return e.Header.SigType
}

func (e *SignatureEnvelope) IsSigstore() bool {
	return e.GetSigType() == SigTypeSigstore
}

func (e *SignatureEnvelope) ValidateForSigstore() error {
	if !e.IsSigstore() {
		return fmt.Errorf("signature is not a Sigstore bundle (sig_type=%s)", e.GetSigType())
	}
	if e.Header == nil {
		return fmt.Errorf("sigstore signature must have a header with canon_version")
	}
	if e.Header.CanonVersion == "" {
		return fmt.Errorf("canon_version is required for Sigstore signatures")
	}
	if len(e.Bundle) == 0 {
		return fmt.Errorf("sigstore signature bundle is empty")
	}
	return nil
}
