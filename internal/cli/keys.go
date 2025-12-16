package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dtang19/mcptrust/internal/crypto"
	"github.com/dtang19/mcptrust/internal/locker"
	"github.com/spf13/cobra"
)

const (
	defaultPrivateKeyPath = "private.key"
	defaultPublicKeyPath  = "public.key"
	defaultSignaturePath  = "mcp-lock.json.sig"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate Ed25519 keypair for signing lockfiles",
	Long: `Generate a new Ed25519 keypair for signing mcp-lock.json files.

This creates two files:
  - private.key: Keep this secret! Used to sign lockfiles.
  - public.key:  Share this with your team to verify signatures.

Example:
  mcptrust keygen
  mcptrust keygen --private my-private.key --public my-public.key`,
	RunE: runKeygen,
}

var (
	keygenPrivateFlag string
	keygenPublicFlag  string
)

func init() {
	keygenCmd.Flags().StringVar(&keygenPrivateFlag, "private", defaultPrivateKeyPath, "Path for the private key file")
	keygenCmd.Flags().StringVar(&keygenPublicFlag, "public", defaultPublicKeyPath, "Path for the public key file")
}

// GetKeygenCmd returns the keygen command
func GetKeygenCmd() *cobra.Command {
	return keygenCmd
}

func runKeygen(cmd *cobra.Command, args []string) error {
	// check existing keys
	if _, err := os.Stat(keygenPrivateFlag); err == nil {
		return fmt.Errorf("private key already exists at %s (use different path or delete existing)", keygenPrivateFlag)
	}
	if _, err := os.Stat(keygenPublicFlag); err == nil {
		return fmt.Errorf("public key already exists at %s (use different path or delete existing)", keygenPublicFlag)
	}

	fmt.Println("Generating Ed25519 keypair...")
	if err := crypto.GenerateKeys(keygenPrivateFlag, keygenPublicFlag); err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	fmt.Printf("%s✓ Private key saved: %s%s\n", colorGreen, keygenPrivateFlag, colorReset)
	fmt.Printf("%s✓ Public key saved:  %s%s\n", colorGreen, keygenPublicFlag, colorReset)
	fmt.Printf("\n%s⚠ Keep your private key secret!%s\n", colorRed, colorReset)

	return nil
}

// signCmd signs lockfiles
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign mcp-lock.json with your private key",
	Long: `Sign the mcp-lock.json lockfile using your Ed25519 private key.

This creates a signature file (mcp-lock.json.sig) that can be used
to verify the lockfile hasn't been tampered with.

The signature is computed over the canonical (deterministic) JSON
representation of the lockfile, ensuring consistent verification.

Example:
  mcptrust sign
  mcptrust sign --lockfile custom-lock.json --key my-private.key`,
	RunE: runSign,
}

var (
	signLockfileFlag         string
	signPrivateKeyFlag       string
	signOutputFlag           string
	signCanonicalizationFlag string
)

func init() {
	signCmd.Flags().StringVarP(&signLockfileFlag, "lockfile", "l", defaultLockfilePath, "Path to the lockfile to sign")
	signCmd.Flags().StringVarP(&signPrivateKeyFlag, "key", "k", defaultPrivateKeyPath, "Path to the private key")
	signCmd.Flags().StringVarP(&signOutputFlag, "output", "o", defaultSignaturePath, "Path for the signature file")
	signCmd.Flags().StringVar(&signCanonicalizationFlag, "canonicalization", "v1", "Canonicalization version (v1 or v2)")
}

func GetSignCmd() *cobra.Command {
	return signCmd
}

func runSign(cmd *cobra.Command, args []string) error {
	// validate canonicalization version
	canonVersion := locker.CanonVersion(signCanonicalizationFlag)
	if canonVersion != locker.CanonV1 && canonVersion != locker.CanonV2 {
		return fmt.Errorf("invalid canonicalization version: %s (use v1 or v2)", signCanonicalizationFlag)
	}

	lockfileData, err := os.ReadFile(signLockfileFlag)
	if err != nil {
		return fmt.Errorf("failed to read lockfile: %w", err)
	}

	// canonicalize for deterministic hashing
	var lockfileJSON interface{}
	if err := json.Unmarshal(lockfileData, &lockfileJSON); err != nil {
		return fmt.Errorf("failed to parse lockfile JSON: %w", err)
	}

	canonicalData, err := locker.CanonicalizeJSONWithVersion(lockfileJSON, canonVersion)
	if err != nil {
		return fmt.Errorf("failed to canonicalize lockfile: %w", err)
	}

	signature, err := crypto.Sign(canonicalData, signPrivateKeyFlag)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// write signature with version header
	sigData := crypto.WriteSignature(signature, string(canonVersion))
	if err := os.WriteFile(signOutputFlag, sigData, 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	fmt.Printf("%s✓ Lockfile signed successfully%s\n", colorGreen, colorReset)
	fmt.Printf("  Signature saved to: %s\n", signOutputFlag)
	fmt.Printf("  Canonicalization: %s\n", canonVersion)

	return nil
}

// verifyCmd verifies signatures
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify mcp-lock.json signature",
	Long: `Verify that the mcp-lock.json lockfile matches its signature.

This checks that the lockfile hasn't been tampered with since it was signed.
Returns exit code 0 if valid, 1 if verification fails.

Example:
  mcptrust verify
  mcptrust verify --lockfile custom-lock.json --signature custom.sig --key my-public.key`,
	SilenceUsage: true,
	RunE:         runVerify,
}

var (
	verifyLockfileFlag  string
	verifySignatureFlag string
	verifyPublicKeyFlag string
)

func init() {
	verifyCmd.Flags().StringVarP(&verifyLockfileFlag, "lockfile", "l", defaultLockfilePath, "Path to the lockfile to verify")
	verifyCmd.Flags().StringVarP(&verifySignatureFlag, "signature", "s", defaultSignaturePath, "Path to the signature file")
	verifyCmd.Flags().StringVarP(&verifyPublicKeyFlag, "key", "k", defaultPublicKeyPath, "Path to the public key")
}

func GetVerifyCmd() *cobra.Command {
	return verifyCmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	lockfileData, err := os.ReadFile(verifyLockfileFlag)
	if err != nil {
		return fmt.Errorf("failed to read lockfile: %w", err)
	}

	// load and parse signature (auto-detects version)
	sigFileData, err := os.ReadFile(verifySignatureFlag)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	envelope, err := crypto.ReadSignature(sigFileData)
	if err != nil {
		return fmt.Errorf("invalid signature file: %w", err)
	}

	// determine canonicalization version from signature
	canonVersion := locker.CanonVersion(envelope.GetCanonVersion())

	// canonicalize for verification using detected version
	var lockfileJSON interface{}
	if err := json.Unmarshal(lockfileData, &lockfileJSON); err != nil {
		return fmt.Errorf("failed to parse lockfile JSON: %w", err)
	}

	canonicalData, err := locker.CanonicalizeJSONWithVersion(lockfileJSON, canonVersion)
	if err != nil {
		return fmt.Errorf("failed to canonicalize lockfile: %w", err)
	}

	valid, err := crypto.Verify(canonicalData, envelope.Signature, verifyPublicKeyFlag)
	if err != nil {
		return fmt.Errorf("verification error: %w", err)
	}

	if valid {
		fmt.Printf("%s✅ Signature Verified%s\n", colorGreen, colorReset)
		return nil
	}

	fmt.Printf("%s❌ TAMPER DETECTED%s\n", colorRed, colorReset)
	os.Exit(1)
	return nil
}
