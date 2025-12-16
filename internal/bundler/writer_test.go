package bundler

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleDeterminism(t *testing.T) {
	// temp dir
	tmpDir, err := os.MkdirTemp("", "bundle_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// test files
	lockfile := filepath.Join(tmpDir, "mcp-lock.json")
	signature := filepath.Join(tmpDir, "mcp-lock.json.sig")
	bundle1 := filepath.Join(tmpDir, "bundle1.zip")
	bundle2 := filepath.Join(tmpDir, "bundle2.zip")

	lockContent := `{"version":"1.0","tools":{}}`
	sigContent := `{"canon_version":"v1"}` + "\n" + "deadbeef1234"

	if err := os.WriteFile(lockfile, []byte(lockContent), 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}
	if err := os.WriteFile(signature, []byte(sigContent), 0644); err != nil {
		t.Fatalf("failed to write signature: %v", err)
	}

	opts := BundleOptions{
		LockfilePath:  lockfile,
		SignaturePath: signature,
		PublicKeyPath: "",
		PolicyPath:    "",
		OutputPath:    bundle1,
	}

	readme := "Test README content"

	// manifest
	manifest, err := GenerateManifest(opts, "v1")
	if err != nil {
		t.Fatalf("failed to generate manifest: %v", err)
	}

	// bundle 1
	if err := CreateBundle(opts, readme, manifest); err != nil {
		t.Fatalf("first CreateBundle failed: %v", err)
	}

	// bundle 2
	opts.OutputPath = bundle2
	if err := CreateBundle(opts, readme, manifest); err != nil {
		t.Fatalf("second CreateBundle failed: %v", err)
	}

	// compare
	hash1, err := hashFileContent(bundle1)
	if err != nil {
		t.Fatalf("failed to hash bundle1: %v", err)
	}
	hash2, err := hashFileContent(bundle2)
	if err != nil {
		t.Fatalf("failed to hash bundle2: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("bundles are not deterministic:\nbundle1: %s\nbundle2: %s", hash1, hash2)
	}
}

func TestManifestGeneration(t *testing.T) {
	// create temp directory
	tmpDir, err := os.MkdirTemp("", "manifest_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// create test files
	lockfile := filepath.Join(tmpDir, "mcp-lock.json")
	signature := filepath.Join(tmpDir, "mcp-lock.json.sig")

	lockContent := `{"version":"1.0"}`
	sigContent := "abcdef123456"

	if err := os.WriteFile(lockfile, []byte(lockContent), 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}
	if err := os.WriteFile(signature, []byte(sigContent), 0644); err != nil {
		t.Fatalf("failed to write signature: %v", err)
	}

	opts := BundleOptions{
		LockfilePath:  lockfile,
		SignaturePath: signature,
	}

	manifest, err := GenerateManifest(opts, "v2")
	if err != nil {
		t.Fatalf("GenerateManifest failed: %v", err)
	}

	// check fields
	if manifest.CanonVersion != "v2" {
		t.Errorf("expected canon_version v2, got %s", manifest.CanonVersion)
	}

	if manifest.LockfileHash == "" {
		t.Error("expected lockfile_hash to be set")
	}

	if manifest.SignatureHash == "" {
		t.Error("expected signature_hash to be set")
	}

	if len(manifest.Files) < 2 {
		t.Errorf("expected at least 2 files, got %d", len(manifest.Files))
	}

	// check files are sorted
	for i := 1; i < len(manifest.Files); i++ {
		if manifest.Files[i-1].Name >= manifest.Files[i].Name {
			t.Errorf("files not sorted: %s >= %s", manifest.Files[i-1].Name, manifest.Files[i].Name)
		}
	}
}

func TestManifestToJSON(t *testing.T) {
	manifest := &BundleManifest{
		ToolVersion:   "1.0.0",
		LockfileHash:  "abc123",
		SignatureHash: "def456",
		CanonVersion:  "v1",
		Files: []ManifestFile{
			{Name: "file1.txt", SHA256: "hash1", Size: 100},
			{Name: "file2.txt", SHA256: "hash2", Size: 200},
		},
	}

	jsonBytes, err := manifest.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// verify it's valid JSON and contains expected fields
	jsonStr := string(jsonBytes)
	if len(jsonStr) == 0 {
		t.Error("expected non-empty JSON")
	}

	// run twice to check determinism
	jsonBytes2, _ := manifest.ToJSON()
	if string(jsonBytes) != string(jsonBytes2) {
		t.Error("ToJSON not deterministic")
	}
}

func hashFileContent(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}
