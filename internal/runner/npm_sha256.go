package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// ComputeTarballSHA256 helper
func ComputeTarballSHA256(tarballPath string) (string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return "", fmt.Errorf("failed to open tarball: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to hash tarball: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// NormalizeSHA256 helper
func NormalizeSHA256(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return ""
	}

	hash = strings.ToLower(hash)

	// Remove "sha256:" prefix if present
	hash = strings.TrimPrefix(hash, "sha256:")

	return hash
}

// VerifySHA256Match
func VerifySHA256Match(expected, actual, context string) error {
	expectedNorm := NormalizeSHA256(expected)
	actualNorm := NormalizeSHA256(actual)

	if expectedNorm != actualNorm {
		return fmt.Errorf("sha256 mismatch (%s):\n  expected: %s\n  actual:   %s",
			context, expected, actual)
	}
	return nil
}
