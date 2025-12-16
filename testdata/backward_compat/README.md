# Backward Compatibility Fixtures

This directory contains fixtures for testing backward compatibility of
signature verification across different signature formats.

## Files

- `legacy_v1_lock.json`: Sample lockfile
- `legacy_v1_sig.hex`: Legacy signature (raw hex, no header) - treated as v1
- `new_v1_sig.txt`: New format signature with v1 header
- `new_v2_sig.txt`: New format signature with v2 header (JCS canonicalization)
- `test_private.key`: Ed25519 private key for signing (TEST ONLY)
- `test_public.key`: Ed25519 public key for verification (TEST ONLY)

## How These Were Generated

```bash
# Generate test keypair
mcptrust keygen --private test_private.key --public test_public.key

# Generate v1 signature (new format with header)
mcptrust sign --lockfile legacy_v1_lock.json --key test_private.key --output new_v1_sig.txt

# Generate v2 signature
mcptrust sign --lockfile legacy_v1_lock.json --key test_private.key --canonicalization v2 --output new_v2_sig.txt

# Legacy format is just the raw hex from new_v1_sig.txt (without the header line)
tail -1 new_v1_sig.txt > legacy_v1_sig.hex
```

## Test Coverage

These fixtures are tested by `internal/crypto/backward_compat_test.go`:
- Legacy signature detection (nil header → v1)
- New v1 signature format parsing
- New v2 signature format parsing
- Full verification with all signature formats
- Tamper detection
- Version mismatch detection

## DO NOT USE THESE KEYS IN PRODUCTION

These are test fixtures only. Generate fresh keys for actual use.
