# Migration & Compatibility

This document describes backward compatibility and migration considerations for MCPTrust updates.

## Canonicalization Versioning (v1.1+)

MCPTrust now supports versioned canonicalization for JSON signing:

- **v1** (default): Original canonicalization algorithm. Keys sorted by Go string comparison.
- **v2**: JCS (RFC 8785) compliant canonicalization. Keys sorted by UTF-16 code units.

### Backward Compatibility

- **Existing signatures work**: Signatures created before this update have no version header and are automatically treated as v1.
- **v1 is default**: New signatures use v1 by default, maintaining full backward compatibility.
- **v2 is opt-in**: Use `--canonicalization v2` only when you specifically need RFC 8785 compliance.

### Signature File Format

New signatures include a JSON header line:
```
{"canon_version":"v1"}
<hex-encoded-signature>
```

Legacy signatures (raw hex only) are auto-detected and verified as v1:
```
<hex-encoded-signature>
```

### When to Use v2

Use v2 canonicalization if:
- You need strict RFC 8785 (JCS) compliance
- You're integrating with systems that require JCS
- You have JSON with edge cases (specific unicode ordering, etc.)

For most use cases, v1 (default) is recommended.

---

## Deterministic Bundle Export (v1.1+)

`bundle export` now produces fully deterministic ZIP bundles:

- Fixed timestamps (2025-01-01 UTC)
- Alphabetical file ordering
- Consistent compression settings

### Bundle Contents

Bundles now include `manifest.json` with:
- Tool version
- File hashes (SHA256) and sizes
- Canonicalization version used
- Lockfile and signature hashes

### Verifying Bundle Integrity

```bash
# Extract and inspect manifest
unzip -p bundle.zip manifest.json | jq .

# Verify signature
unzip bundle.zip -d extracted/
mcptrust verify -l extracted/mcp-lock.json \
  -s extracted/mcp-lock.json.sig \
  -k extracted/public.key
```

---

## Version Compatibility Matrix

| mcptrust version | Reads v1 sigs | Reads v2 sigs | Writes v1 | Writes v2 |
|------------------|---------------|---------------|-----------|-----------|
| < 1.1            | ✓             | ✗             | ✓         | ✗         |
| ≥ 1.1            | ✓             | ✓             | ✓         | ✓         |

Signatures created with v2 cannot be verified by older versions. Use v1 (default) for maximum compatibility.
