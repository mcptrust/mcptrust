package crypto

import (
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
