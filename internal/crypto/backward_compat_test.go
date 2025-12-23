package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mcptrust/mcptrust/internal/locker"
)

// TestBackwardCompatibility_LegacyV1Signature tests that legacy signatures
// (raw hex, no header) are correctly detected as v1 and verify successfully.
func TestBackwardCompatibility_LegacyV1Signature(t *testing.T) {
	fixtureDir := "../../testdata/backward_compat"

	sigData, err := os.ReadFile(filepath.Join(fixtureDir, "legacy_v1_sig.hex"))
	if err != nil {
		t.Fatalf("failed to read legacy signature: %v", err)
	}

	env, err := ReadSignature(sigData)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if env.Header != nil {
		t.Error("expected nil header for legacy signature")
	}
	if env.GetCanonVersion() != "v1" {
		t.Errorf("expected v1, got %s", env.GetCanonVersion())
	}
}

// TestBackwardCompatibility_NewV1Signature tests new format v1 signatures
func TestBackwardCompatibility_NewV1Signature(t *testing.T) {
	fixtureDir := "../../testdata/backward_compat"

	sigData, err := os.ReadFile(filepath.Join(fixtureDir, "new_v1_sig.txt"))
	if err != nil {
		t.Fatalf("failed to read v1 signature: %v", err)
	}

	env, err := ReadSignature(sigData)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if env.Header == nil {
		t.Error("expected header for new v1 signature")
	}
	if env.GetCanonVersion() != "v1" {
		t.Errorf("expected v1, got %s", env.GetCanonVersion())
	}
}

// TestBackwardCompatibility_NewV2Signature tests new format v2 signatures
func TestBackwardCompatibility_NewV2Signature(t *testing.T) {
	fixtureDir := "../../testdata/backward_compat"

	sigData, err := os.ReadFile(filepath.Join(fixtureDir, "new_v2_sig.txt"))
	if err != nil {
		t.Fatalf("failed to read v2 signature: %v", err)
	}

	env, err := ReadSignature(sigData)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	if env.Header == nil {
		t.Error("expected header for v2 signature")
	}
	if env.GetCanonVersion() != "v2" {
		t.Errorf("expected v2, got %s", env.GetCanonVersion())
	}
}

// TestBackwardCompatibility_FullVerification tests end-to-end verification
// using actual fixtures: legacy_v1_lock.json with both signature formats
func TestBackwardCompatibility_FullVerification(t *testing.T) {
	fixtureDir := "../../testdata/backward_compat"

	lockData, err := os.ReadFile(filepath.Join(fixtureDir, "legacy_v1_lock.json"))
	if err != nil {
		t.Fatalf("failed to read lockfile: %v", err)
	}

	testCases := []struct {
		name    string
		sigFile string
		version string
	}{
		{"legacy_v1", "legacy_v1_sig.hex", "v1"},
		{"new_v1", "new_v1_sig.txt", "v1"},
		{"new_v2", "new_v2_sig.txt", "v2"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sigData, err := os.ReadFile(filepath.Join(fixtureDir, tc.sigFile))
			if err != nil {
				t.Fatalf("failed to read signature: %v", err)
			}

			env, err := ReadSignature(sigData)
			if err != nil {
				t.Fatalf("ReadSignature failed: %v", err)
			}

			if env.GetCanonVersion() != tc.version {
				t.Errorf("expected %s, got %s", tc.version, env.GetCanonVersion())
			}

			var lockJSON interface{}
			if err := json.Unmarshal(lockData, &lockJSON); err != nil {
				t.Fatalf("failed to parse lockfile: %v", err)
			}

			canonVersion := locker.CanonVersion(env.GetCanonVersion())
			canonical, err := locker.CanonicalizeJSONWithVersion(lockJSON, canonVersion)
			if err != nil {
				t.Fatalf("canonicalization failed: %v", err)
			}

			valid, err := Verify(canonical, env.Signature, filepath.Join(fixtureDir, "test_public.key"))
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if !valid {
				t.Errorf("%s: signature verification failed", tc.name)
			}
		})
	}
}

// TestBackwardCompatibility_TamperedLockfile verifies detection of modified content
func TestBackwardCompatibility_TamperedLockfile(t *testing.T) {
	fixtureDir := "../../testdata/backward_compat"

	tamperedLock := []byte(`{
  "version": "1.0",
  "server_command": "mock-server",
  "tools": {
    "read_file": {
      "description_hash": "sha256:TAMPERED_HASH_12345678901234567890123456789012345678901234",
      "input_schema_hash": "sha256:def456abc123789012345678901234567890123456789012345678901234",
      "risk_level": "LOW"
    }
  }
}`)

	sigData, err := os.ReadFile(filepath.Join(fixtureDir, "new_v1_sig.txt"))
	if err != nil {
		t.Fatalf("failed to read signature: %v", err)
	}

	env, err := ReadSignature(sigData)
	if err != nil {
		t.Fatalf("ReadSignature failed: %v", err)
	}

	var lockJSON interface{}
	if err := json.Unmarshal(tamperedLock, &lockJSON); err != nil {
		t.Fatalf("failed to parse lockfile: %v", err)
	}

	canonVersion := locker.CanonVersion(env.GetCanonVersion())
	canonical, err := locker.CanonicalizeJSONWithVersion(lockJSON, canonVersion)
	if err != nil {
		t.Fatalf("canonicalization failed: %v", err)
	}

	valid, err := Verify(canonical, env.Signature, filepath.Join(fixtureDir, "test_public.key"))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if valid {
		t.Error("expected verification to FAIL for tampered lockfile")
	}
}

// TestBackwardCompatibility_VersionMismatch tests that using wrong canon version fails
// Note: This test uses a JSON structure where v1 and v2 produce different output.
// The simple fixture lockfile has sorted keys, so v1/v2 produce identical output.
// This test constructs a JSON with keys that sort differently by UTF-16 vs byte order.
func TestBackwardCompatibility_VersionMismatch(t *testing.T) {
	fixtureDir := "../../testdata/backward_compat"

	testData := map[string]interface{}{
		"z": "last",
		"🎉": "party",
		"a": "first",
	}

	v1Bytes, err := locker.CanonicalizeJSONv1(testData)
	if err != nil {
		t.Fatalf("v1 canonicalization failed: %v", err)
	}

	v2Bytes, err := locker.CanonicalizeJSONv2(testData)
	if err != nil {
		t.Fatalf("v2 canonicalization failed: %v", err)
	}

	if string(v1Bytes) == string(v2Bytes) {
		t.Skip("v1 and v2 produce identical output for test data, cannot test version mismatch")
	}

	v1Sig, err := Sign(v1Bytes, filepath.Join(fixtureDir, "test_private.key"))
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	valid, err := Verify(v2Bytes, v1Sig, filepath.Join(fixtureDir, "test_public.key"))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if valid {
		t.Error("expected verification to FAIL when signature was computed over different canonical bytes")
	}
}
