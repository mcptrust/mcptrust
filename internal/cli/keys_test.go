package cli

import (
	"testing"
)

// TestVerifyCmd_HiddenFlagsExist checks hidden flags
func TestVerifyCmd_HiddenFlagsExist(t *testing.T) {
	cmd := GetVerifyCmd()

	tests := []struct {
		flagName string
	}{
		{"force-sigstore"},
		{"force-ed25519"},
	}

	for _, tc := range tests {
		t.Run(tc.flagName, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tc.flagName)
			if flag == nil {
				t.Errorf("expected hidden flag %q to be registered", tc.flagName)
			}
		})
	}
}

// TestVerifyCmd_RequiredFlags checks presence
func TestVerifyCmd_RequiredFlags(t *testing.T) {
	cmd := GetVerifyCmd()

	requiredFlags := []string{
		"lockfile",
		"signature",
		"key",
		"issuer",
		"identity",
		"identity-regexp",
		"github-actions",
	}

	for _, name := range requiredFlags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Errorf("expected flag %q to be registered", name)
			}
		})
	}
}

// TestSignCmd_FlagsExist checks presence
func TestSignCmd_FlagsExist(t *testing.T) {
	cmd := GetSignCmd()

	flags := []string{
		"lockfile",
		"key",
		"output",
		"canonicalization",
		"sigstore",
		"bundle-out",
	}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Errorf("expected flag %q to be registered", name)
			}
		})
	}
}

// TestKeygenCmd_FlagsExist checks presence
func TestKeygenCmd_FlagsExist(t *testing.T) {
	cmd := GetKeygenCmd()

	flags := []string{
		"private",
		"public",
	}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Errorf("expected flag %q to be registered", name)
			}
		})
	}
}
