package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteSignature(t *testing.T) {
	sig := []byte{0xde, 0xad, 0xbe, 0xef}
	result := WriteSignature(sig, "v1")

	expected := "{\"canon_version\":\"v1\"}\ndeadbeef"
	if string(result) != expected {
		t.Errorf("WriteSignature:\nexpected: %s\ngot:      %s", expected, result)
	}
}

func TestReadSignature_NewFormat(t *testing.T) {
	// new format with header
	data := []byte("{\"canon_version\":\"v2\"}\nabcdef1234567890")

	env, err := ReadSignature(data)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if env.Header == nil {
		t.Fatal("expected header to be present")
	}
	if env.Header.CanonVersion != "v2" {
		t.Errorf("expected v2, got %s", env.Header.CanonVersion)
	}
	if env.GetCanonVersion() != "v2" {
		t.Errorf("GetCanonVersion expected v2, got %s", env.GetCanonVersion())
	}
}

func TestReadSignature_LegacyFormat(t *testing.T) {
	// legacy format: raw hex only
	data := []byte("deadbeef12345678")

	env, err := ReadSignature(data)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if env.Header != nil {
		t.Error("expected no header for legacy format")
	}
	if env.GetCanonVersion() != "v1" {
		t.Errorf("legacy should default to v1, got %s", env.GetCanonVersion())
	}
}

func TestReadSignature_RoundTrip(t *testing.T) {
	sig := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// write signature
	data := WriteSignature(sig, "v2")

	// read it back
	env, err := ReadSignature(data)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if env.GetCanonVersion() != "v2" {
		t.Errorf("expected v2, got %s", env.GetCanonVersion())
	}

	// compare signatures
	if len(env.Signature) != len(sig) {
		t.Fatalf("signature length mismatch: %d vs %d", len(env.Signature), len(sig))
	}
	for i := range sig {
		if env.Signature[i] != sig[i] {
			t.Errorf("signature byte %d mismatch: %02x vs %02x", i, env.Signature[i], sig[i])
		}
	}
}

func TestReadSignature_InvalidHex(t *testing.T) {
	data := []byte("not-valid-hex!")
	_, err := ReadSignature(data)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestReadSignature_InvalidHeader(t *testing.T) {
	data := []byte("{invalid-json}\nabcdef")
	_, err := ReadSignature(data)
	if err == nil {
		t.Error("expected error for invalid header JSON")
	}
}

// === Sigstore v3 format tests ===

func TestWriteSigstoreSignature(t *testing.T) {
	bundle := []byte(`{"test":"bundle","rekorBundle":{"signedEntryTimestamp":"abc"}}`)
	result, err := WriteSigstoreSignature(bundle, "v1")
	if err != nil {
		t.Fatalf("WriteSigstoreSignature failed: %v", err)
	}

	env, err := ReadSignature(result)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if env.Header == nil {
		t.Fatal("expected header")
	}
	if env.Header.SigType != SigTypeSigstore {
		t.Errorf("expected sig_type=%s, got %s", SigTypeSigstore, env.Header.SigType)
	}
	if env.Header.BundleEnc != "base64+json" {
		t.Errorf("expected bundle_encoding=base64+json, got %s", env.Header.BundleEnc)
	}
}

func TestReadSignature_SigstoreFormat(t *testing.T) {
	bundle := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.1"}`)
	sigData, err := WriteSigstoreSignature(bundle, "v1")
	if err != nil {
		t.Fatalf("WriteSigstoreSignature failed: %v", err)
	}

	env, err := ReadSignature(sigData)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if !env.IsSigstore() {
		t.Error("expected IsSigstore() to be true")
	}
	if env.GetSigType() != SigTypeSigstore {
		t.Errorf("expected sig_type=%s, got %s", SigTypeSigstore, env.GetSigType())
	}
	if env.Bundle == nil {
		t.Fatal("expected bundle to be populated")
	}
	if !bytes.Equal(env.Bundle, bundle) {
		t.Errorf("bundle mismatch:\nexpected: %s\ngot:      %s", bundle, env.Bundle)
	}
}

func TestReadSignature_SigstoreRoundTrip(t *testing.T) {
	originalBundle := []byte(`{"rekorBundle":{"logIndex":"12345"},"cert":"base64cert"}`)

	// Write
	sigData, err := WriteSigstoreSignature(originalBundle, "v2")
	if err != nil {
		t.Fatalf("WriteSigstoreSignature failed: %v", err)
	}

	// Read back
	env, err := ReadSignature(sigData)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if env.GetCanonVersion() != "v2" {
		t.Errorf("expected canon v2, got %s", env.GetCanonVersion())
	}
	if !env.IsSigstore() {
		t.Error("expected sigstore type")
	}
	if !bytes.Equal(env.Bundle, originalBundle) {
		t.Errorf("bundle mismatch")
	}
}

func TestReadSignature_InvalidBase64Bundle(t *testing.T) {
	// Sigstore header but invalid base64 payload
	data := []byte(`{"canon_version":"v1","sig_type":"sigstore_bundle","bundle_encoding":"base64+json"}
not-valid-base64!!!`)

	_, err := ReadSignature(data)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestGetSigType_DefaultsToEd25519(t *testing.T) {
	// Legacy format
	env := &SignatureEnvelope{Header: nil}
	if env.GetSigType() != SigTypeEd25519 {
		t.Errorf("legacy should default to ed25519, got %s", env.GetSigType())
	}

	// Header without sig_type
	env2 := &SignatureEnvelope{Header: &SignatureHeader{CanonVersion: "v1"}}
	if env2.GetSigType() != SigTypeEd25519 {
		t.Errorf("empty sig_type should default to ed25519, got %s", env2.GetSigType())
	}
}

func TestIsSigstore(t *testing.T) {
	tests := []struct {
		name     string
		env      *SignatureEnvelope
		expected bool
	}{
		{"legacy", &SignatureEnvelope{Header: nil}, false},
		{"ed25519 header", &SignatureEnvelope{Header: &SignatureHeader{SigType: SigTypeEd25519}}, false},
		{"sigstore header", &SignatureEnvelope{Header: &SignatureHeader{SigType: SigTypeSigstore}}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env.IsSigstore() != tc.expected {
				t.Errorf("IsSigstore() = %v, want %v", tc.env.IsSigstore(), tc.expected)
			}
		})
	}
}

// === Patch #6: canon_version enforcement tests ===

func TestWriteSigstoreSignature_RequiresCanonVersion(t *testing.T) {
	bundle := []byte(`{"test":"bundle"}`)

	// Empty canon_version should fail
	_, err := WriteSigstoreSignature(bundle, "")
	if err == nil {
		t.Fatal("expected error for empty canon_version")
	}
	if !strings.Contains(err.Error(), "canon_version is required") {
		t.Errorf("error should mention canon_version, got: %v", err)
	}

	// Non-empty should succeed
	_, err = WriteSigstoreSignature(bundle, "v1")
	if err != nil {
		t.Errorf("unexpected error for valid canon_version: %v", err)
	}
}

func TestValidateForSigstore_RequiresCanonVersion(t *testing.T) {
	tests := []struct {
		name      string
		env       *SignatureEnvelope
		wantError string
	}{
		{
			name:      "missing header",
			env:       &SignatureEnvelope{Header: nil, Bundle: []byte(`{}`)},
			wantError: "not a Sigstore bundle",
		},
		{
			name: "empty canon_version",
			env: &SignatureEnvelope{
				Header: &SignatureHeader{SigType: SigTypeSigstore, CanonVersion: ""},
				Bundle: []byte(`{}`),
			},
			wantError: "canon_version is required",
		},
		{
			name: "empty bundle",
			env: &SignatureEnvelope{
				Header: &SignatureHeader{SigType: SigTypeSigstore, CanonVersion: "v1"},
				Bundle: nil,
			},
			wantError: "bundle is empty",
		},
		{
			name: "valid",
			env: &SignatureEnvelope{
				Header: &SignatureHeader{SigType: SigTypeSigstore, CanonVersion: "v1"},
				Bundle: []byte(`{"valid":"bundle"}`),
			},
			wantError: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.env.ValidateForSigstore()
			if tc.wantError == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error but got nil")
				} else if !strings.Contains(err.Error(), tc.wantError) {
					t.Errorf("error should contain %q, got: %v", tc.wantError, err)
				}
			}
		})
	}
}
