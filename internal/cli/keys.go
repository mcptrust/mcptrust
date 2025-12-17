package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mcptrust/mcptrust/internal/crypto"
	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/sigstore"
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
	Short: "Generate Ed25519 keypair",
	Long: `Generate a new Ed25519 keypair for signing lockfiles.

Creates:
  - private.key: Secret signing key.
  - public.key:  Public verification key.

Example:
  mcptrust keygen
  mcptrust keygen --private my.key --public my.pub`,
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
	Short: "Sign mcp-lock.json with Ed25519 or Sigstore",
	Long: `Sign the lockfile using Ed25519 key or Sigstore keyless.

Ed25519 (default):
  Signs using local private key. Needs --key.

Sigstore (--sigstore):
  Keyless signing via OIDC (GitHub Actions or browser).
  Requires 'cosign' installed.

The signature covers the canonical (deterministic) JSON.

Examples:
  # Ed25519
  mcptrust sign --key private.key

  # Sigstore (CI/CD)
  mcptrust sign --sigstore

  # Custom file
  mcptrust sign --sigstore --lockfile custom.json`,
	RunE: runSign,
}

var (
	signLockfileFlag         string
	signPrivateKeyFlag       string
	signOutputFlag           string
	signCanonicalizationFlag string
	signSigstoreFlag         bool
	signBundleOutFlag        string
)

func init() {
	signCmd.Flags().StringVarP(&signLockfileFlag, "lockfile", "l", defaultLockfilePath, "Path to the lockfile to sign")
	signCmd.Flags().StringVarP(&signPrivateKeyFlag, "key", "k", "", "Path to the private key (Ed25519 mode)")
	signCmd.Flags().StringVarP(&signOutputFlag, "output", "o", "", "Path for the signature file (default: <lockfile>.sig)")
	signCmd.Flags().StringVar(&signCanonicalizationFlag, "canonicalization", "v1", "Canonicalization version (v1 or v2)")
	signCmd.Flags().BoolVar(&signSigstoreFlag, "sigstore", false, "Use Sigstore keyless signing (requires cosign)")
	signCmd.Flags().StringVar(&signBundleOutFlag, "bundle-out", "", "Also write raw Sigstore bundle to this path")
}

func GetSignCmd() *cobra.Command {
	return signCmd
}

func runSign(cmd *cobra.Command, args []string) error {
	// Determine output path
	outputPath := signOutputFlag
	if outputPath == "" {
		outputPath = signLockfileFlag + ".sig"
	}

	// Validate mode selection
	if signSigstoreFlag && signPrivateKeyFlag != "" {
		return fmt.Errorf("cannot use both --sigstore and --key flags")
	}
	if !signSigstoreFlag && signPrivateKeyFlag == "" {
		// Default to Ed25519 with default key path
		signPrivateKeyFlag = defaultPrivateKeyPath
	}

	// Validate canonicalization version
	canonVersion := locker.CanonVersion(signCanonicalizationFlag)
	if canonVersion != locker.CanonV1 && canonVersion != locker.CanonV2 {
		return fmt.Errorf("invalid canonicalization version: %s (use v1 or v2)", signCanonicalizationFlag)
	}

	// read and canonicalize
	lockfileData, err := os.ReadFile(signLockfileFlag)
	if err != nil {
		return fmt.Errorf("failed to read lockfile: %w", err)
	}

	var lockfileJSON interface{}
	if err := json.Unmarshal(lockfileData, &lockfileJSON); err != nil {
		return fmt.Errorf("failed to parse lockfile JSON: %w", err)
	}

	canonicalData, err := locker.CanonicalizeJSONWithVersion(lockfileJSON, canonVersion)
	if err != nil {
		return fmt.Errorf("failed to canonicalize lockfile: %w", err)
	}

	if signSigstoreFlag {
		return runSignSigstore(canonicalData, canonVersion, outputPath)
	}

	return runSignEd25519(canonicalData, canonVersion, outputPath)
}

func runSignEd25519(canonicalData []byte, canonVersion locker.CanonVersion, outputPath string) error {
	signature, err := crypto.Sign(canonicalData, signPrivateKeyFlag)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// write signature with version header
	sigData := crypto.WriteSignature(signature, string(canonVersion))
	if err := os.WriteFile(outputPath, sigData, 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	fmt.Printf("%s✓ Lockfile signed successfully%s\n", colorGreen, colorReset)
	fmt.Printf("  Signature saved to: %s\n", outputPath)
	fmt.Printf("  Canonicalization: %s\n", canonVersion)
	fmt.Printf("  Mode: Ed25519\n")

	return nil
}

func runSignSigstore(canonicalData []byte, canonVersion locker.CanonVersion, outputPath string) error {
	// Write canonical data to temp file
	tempFile, err := os.CreateTemp("", "mcptrust-sign-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	if _, err := tempFile.Write(canonicalData); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	tempFile.Close()

	// Sign with cosign
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// runner mode: interactive vs captured
	runner := sigstore.GetRunner()
	if sigstore.IsInteractive() {
		fmt.Println("Signing with Sigstore (keyless)...")
		fmt.Println("  A browser window will open for authentication.")
	} else {
		fmt.Println("Signing with Sigstore (keyless)...")
	}

	bundleJSON, err := sigstore.SignBundle(ctx, tempPath, runner)
	if err != nil {
		return fmt.Errorf("sigstore signing failed: %w", err)
	}

	// Write raw bundle if requested
	if signBundleOutFlag != "" {
		if err := os.WriteFile(signBundleOutFlag, bundleJSON, 0644); err != nil {
			return fmt.Errorf("failed to write bundle: %w", err)
		}
		fmt.Printf("  Raw bundle saved to: %s\n", signBundleOutFlag)
	}

	// Write signature envelope
	sigData, err := crypto.WriteSigstoreSignature(bundleJSON, string(canonVersion))
	if err != nil {
		return fmt.Errorf("failed to create signature envelope: %w", err)
	}
	if err := os.WriteFile(outputPath, sigData, 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	fmt.Printf("%s✓ Lockfile signed successfully (Sigstore keyless)%s\n", colorGreen, colorReset)
	fmt.Printf("  Signature saved to: %s\n", outputPath)
	fmt.Printf("  Canonicalization: %s\n", canonVersion)
	fmt.Printf("  Mode: Sigstore (keyless OIDC)\n")

	return nil
}

// verifyCmd verifies signatures
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify lockfile signature",
	Long: `Verify that the lockfile matches its signature.

Auto-detects signature type:
- Ed25519: needs --key
- Sigstore: needs --issuer and --identity (or --identity-regexp)

For Sigstore, you must matching the OIDC issuer and identity to
prevent impersonation.

Examples:
  # Ed25519
  mcptrust verify --key public.key

  # Sigstore (GitHub Actions)
  mcptrust verify \
    --issuer https://token.actions.githubusercontent.com \
    --identity "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main"

  # Sigstore (regex)
  mcptrust verify \
    --issuer https://token.actions.githubusercontent.com \
    --identity-regexp "https://github.com/org/repo/.*"

Exit codes:
  0 = Valid
  1 = Invalid`,
	SilenceUsage: true,
	RunE:         runVerify,
}

var (
	verifyLockfileFlag       string
	verifySignatureFlag      string
	verifyPublicKeyFlag      string
	verifyIssuerFlag         string
	verifyIdentityFlag       string
	verifyIdentityRegexpFlag string
	verifyGitHubActionsFlag  bool
	verifyForceSigstoreFlag  bool
	verifyForceEd25519Flag   bool
)

func init() {
	verifyCmd.Flags().StringVarP(&verifyLockfileFlag, "lockfile", "l", defaultLockfilePath, "Path to the lockfile to verify")
	verifyCmd.Flags().StringVarP(&verifySignatureFlag, "signature", "s", "", "Path to the signature file (default: <lockfile>.sig)")
	verifyCmd.Flags().StringVarP(&verifyPublicKeyFlag, "key", "k", "", "Path to the public key (Ed25519 mode)")

	// Sigstore options
	verifyCmd.Flags().StringVar(&verifyIssuerFlag, "issuer", "", "Expected OIDC issuer")
	verifyCmd.Flags().StringVar(&verifyIdentityFlag, "identity", "", "Expected certificate identity (SAN)")
	verifyCmd.Flags().StringVar(&verifyIdentityRegexpFlag, "identity-regexp", "", "Regexp pattern for identity")
	verifyCmd.Flags().BoolVar(&verifyGitHubActionsFlag, "github-actions", false, "Preset: use GitHub Actions issuer")

	// debug/force
	verifyCmd.Flags().BoolVar(&verifyForceSigstoreFlag, "force-sigstore", false, "Force Sigstore mode")
	verifyCmd.Flags().BoolVar(&verifyForceEd25519Flag, "force-ed25519", false, "Force Ed25519 mode")
	// ignore hide error
	_ = verifyCmd.Flags().MarkHidden("force-sigstore")
	_ = verifyCmd.Flags().MarkHidden("force-ed25519")
}

func GetVerifyCmd() *cobra.Command {
	return verifyCmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	// Determine signature path
	sigPath := verifySignatureFlag
	if sigPath == "" {
		sigPath = verifyLockfileFlag + ".sig"
	}

	// Read lockfile
	lockfileData, err := os.ReadFile(verifyLockfileFlag)
	if err != nil {
		return fmt.Errorf("failed to read lockfile: %w", err)
	}

	// Read and parse signature
	sigFileData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	envelope, err := crypto.ReadSignature(sigFileData)
	if err != nil {
		return fmt.Errorf("invalid signature file: %w", err)
	}

	// Determine verification mode
	useSigstore := envelope.IsSigstore()
	if verifyForceSigstoreFlag {
		useSigstore = true
	}
	if verifyForceEd25519Flag {
		useSigstore = false
	}

	// Apply GitHub Actions preset
	if verifyGitHubActionsFlag {
		if verifyIssuerFlag == "" {
			verifyIssuerFlag = sigstore.GitHubActionsIssuer
		}
	}

	if useSigstore {
		return runVerifySigstore(lockfileData, envelope, sigPath)
	}

	return runVerifyEd25519(lockfileData, envelope)
}

func runVerifyEd25519(lockfileData []byte, envelope *crypto.SignatureEnvelope) error {
	// Use default key if not specified
	keyPath := verifyPublicKeyFlag
	if keyPath == "" {
		keyPath = defaultPublicKeyPath
	}

	// Determine canonicalization version from signature
	canonVersion := locker.CanonVersion(envelope.GetCanonVersion())

	// Canonicalize for verification
	var lockfileJSON interface{}
	if err := json.Unmarshal(lockfileData, &lockfileJSON); err != nil {
		return fmt.Errorf("failed to parse lockfile JSON: %w", err)
	}

	canonicalData, err := locker.CanonicalizeJSONWithVersion(lockfileJSON, canonVersion)
	if err != nil {
		return fmt.Errorf("failed to canonicalize lockfile: %w", err)
	}

	valid, err := crypto.Verify(canonicalData, envelope.Signature, keyPath)
	if err != nil {
		return fmt.Errorf("verification error: %w", err)
	}

	if valid {
		fmt.Printf("%s✅ Signature Verified%s\n", colorGreen, colorReset)
		fmt.Printf("  Mode: Ed25519\n")
		fmt.Printf("  Canonicalization: %s\n", canonVersion)
		return nil
	}

	fmt.Printf("%s❌ TAMPER DETECTED%s\n", colorRed, colorReset)
	os.Exit(1)
	return nil
}

func runVerifySigstore(lockfileData []byte, envelope *crypto.SignatureEnvelope, sigPath string) error {
	// Validate required params
	if verifyIssuerFlag == "" {
		return fmt.Errorf("--issuer is required for Sigstore verification (or use --github-actions preset)")
	}
	if verifyIdentityFlag == "" && verifyIdentityRegexpFlag == "" {
		return fmt.Errorf("--identity or --identity-regexp is required for Sigstore verification")
	}

	if envelope.Bundle == nil {
		return fmt.Errorf("signature file does not contain a Sigstore bundle")
	}

	// Determine canonicalization version
	canonVersion := locker.CanonVersion(envelope.GetCanonVersion())
	if canonVersion == "" {
		return fmt.Errorf("canon_version is required for Sigstore signatures")
	}

	// Canonicalize lockfile
	var lockfileJSON interface{}
	if err := json.Unmarshal(lockfileData, &lockfileJSON); err != nil {
		return fmt.Errorf("failed to parse lockfile JSON: %w", err)
	}

	canonicalData, err := locker.CanonicalizeJSONWithVersion(lockfileJSON, canonVersion)
	if err != nil {
		return fmt.Errorf("failed to canonicalize lockfile: %w", err)
	}

	// Write canonical data to temp file
	tempFile, err := os.CreateTemp("", "mcptrust-verify-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	if _, err := tempFile.Write(canonicalData); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	tempFile.Close()

	// Verify with cosign
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := sigstore.VerifyBundle(ctx, tempPath, envelope.Bundle,
		verifyIssuerFlag, verifyIdentityFlag, verifyIdentityRegexpFlag, nil)
	if err != nil {
		return fmt.Errorf("sigstore verification failed: %w", err)
	}

	if result.Valid {
		fmt.Printf("%s✅ Signature Verified%s\n", colorGreen, colorReset)
		fmt.Printf("  Mode: Sigstore (keyless OIDC)\n")
		fmt.Printf("  Issuer: %s\n", verifyIssuerFlag)
		if verifyIdentityFlag != "" {
			fmt.Printf("  Identity: %s\n", verifyIdentityFlag)
		} else {
			fmt.Printf("  Identity pattern: %s\n", verifyIdentityRegexpFlag)
		}
		fmt.Printf("  Canonicalization: %s\n", canonVersion)
		return nil
	}

	fmt.Printf("%s❌ VERIFICATION FAILED%s\n", colorRed, colorReset)
	if result.Message != "" {
		fmt.Printf("  Reason: %s\n", result.Message)
	}
	fmt.Printf("  Expected issuer: %s\n", verifyIssuerFlag)
	if verifyIdentityFlag != "" {
		fmt.Printf("  Expected identity: %s\n", verifyIdentityFlag)
	}
	// Help the user fix policy
	absPath, _ := filepath.Abs(sigPath)
	fmt.Printf("\n  Tip: Check the actual identity in the signature with:\n")
	fmt.Printf("    cosign verify-blob --bundle <bundle.json> --certificate-identity-regexp '.*' \\\n")
	fmt.Printf("      --certificate-oidc-issuer '%s' <lockfile>\n", verifyIssuerFlag)
	fmt.Printf("  Signature file: %s\n", absPath)

	os.Exit(1)
	return nil
}
