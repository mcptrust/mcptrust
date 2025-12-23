# Release Notes

## MCPTrust v2.0 - Supply Chain Security

### New Features

#### Artifact Pinning (`--pin`)
Lock npm packages and OCI images with cryptographic integrity hashes:
```bash
mcptrust lock --pin -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
```
The lockfile now records package name, version, registry, and integrity hash.

#### Provenance Verification (`--verify-provenance`)
Verify SLSA provenance attestations to confirm build origin:
```bash
mcptrust lock --pin --verify-provenance -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
```
Uses cosign (primary) or npm audit signatures (fallback).

#### Artifact Subcommands
New commands for post-lock verification:
```bash
mcptrust artifact verify mcp-lock.json      # Check integrity
mcptrust artifact provenance mcp-lock.json  # Re-verify provenance
```

#### Policy Presets (`--preset`)
Built-in governance policies for common use cases:
- `baseline`: Warn-only mode (exit 0 with warnings) for gradual adoption
- `strict`: Fail-closed mode (exit 1 on violations) for production

```bash
mcptrust policy check --preset baseline -- "npx -y ..."
mcptrust policy check --preset strict --lockfile mcp-lock.json -- "npx -y ..."
```

#### Lockfile-Based Policy Evaluation (`--lockfile`)
Policies can now access artifact and provenance data:
```yaml
rules:
  - name: "artifact_pinned"
    expr: 'has(input.artifact) && input.artifact.integrity != ""'
  - name: "trusted_source"
    expr: 'input.provenance.source_repo.matches("^https://github.com/trusted/")'
```

### Detection vs Enforcement

> [!IMPORTANT]
> MCPTrust **verifies and detects** integrity/provenance issues but does not control runtime execution. The pinned artifact is verified against registry state—it does not guarantee `npx` resolves the same package at execution time.
>
> For enforcement, use explicit version pinning in your CI scripts.

### Tooling Requirements

| Tool | Required | Purpose |
|------|----------|---------|
| cosign | Recommended | Primary provenance verification (uses >= v2.4.1 features) |
| npm | Fallback | `npm audit signatures` fallback (>= 9.5.0) |

### Breaking Changes

None. All existing CLI flags and lockfile formats remain backward compatible.

### Behavior Changes

#### Tarball Redirect Policy

**Changed:** Tarball downloads now allow up to 5 validated redirects instead of blocking all redirects.

| Previous Behavior | New Behavior |
|-------------------|--------------|
| All HTTP redirects blocked | Up to 5 redirects allowed |
| - | Each hop validated (HTTPS required, no private IPs) |
| - | Scheme downgrade (HTTPS → HTTP) blocked |

**Why:** npm registries commonly redirect to CDN hosts. The previous "block all redirects" policy caused failures for some packages. The new policy maintains security (each hop is fully validated) while improving compatibility.

**Security note:** Hash verification remains the trust anchor. Even if redirects occur, the downloaded tarball must match the pinned integrity hash.

#### Unified Tarball Downloader

All tarball downloads (runner, artifact verification, provenance) now use a single consolidated implementation (`internal/netutil`). This ensures consistent security behavior across all code paths.

### Upgrade Path

1. Update MCPTrust: `go install github.com/mcptrust/mcptrust/cmd/mcptrust@v0.1.1`
2. Re-lock with pinning: `mcptrust lock --pin -- "your-server-command"`
3. Optionally verify provenance: `mcptrust lock --pin --verify-provenance -- "..."`
4. Update CI to use policy presets if desired

---

## MCPTrust v2.1 - Provenance Verification Semantics Fix

### Behavior Changes

#### Provenance Verification Method Disambiguation

Provenance verification now explicitly tracks the verification method to prevent misleading claims.

| Method | Output Message | SLSA Metadata |
|--------|----------------|---------------|
| `cosign_slsa` | "✓ Provenance verified" | source_repo, workflow_uri, builder_id populated |
| `npm_audit_signatures` | "✓ Package signature verified (npm audit signatures)" | SLSA fields NOT available |
| `unverified` | (provenance not verified) | N/A |

**Breaking change:** `--expected-source` now requires cosign verification. Using `--expected-source` with npm audit signatures fallback returns a hard error:
```
--expected-source requires SLSA provenance (cosign). npm audit signatures do not expose configSource.uri
```

#### Policy Input Honesty

`input.provenance` is now only populated in CEL policy input when the provenance method is `cosign_slsa`. This prevents policies from accidentally passing when npm fallback was used (which doesn't populate SLSA metadata fields).

Policies relying on `input.provenance.source_repo` or similar fields will correctly fail when only npm signatures are available.

### New Fields

The `ProvenanceInfo` struct now includes a `method` field in the lockfile:
```json
{
  "provenance": {
    "method": "cosign_slsa",
    "verified": true,
    "source_repo": "https://github.com/org/repo",
    ...
  }
}
```

### Security Fixes

#### Runner `--require-provenance` Enforcement (v2.1.1)

**Fixed:** The `mcptrust run` command's `--require-provenance` flag now correctly requires `method == cosign_slsa`. Previously, npm audit signatures were incorrectly satisfying this gate.

| Before (Bug) | After (Fixed) |
|--------------|---------------|
| `npm_audit_signatures` bypassed require-provenance | `npm_audit_signatures` fails require-provenance with clear error |
| Checked `Verified == true` only | Checks `Method == cosign_slsa` |

**New error message:**
```
SLSA provenance required; npm audit signatures are not sufficient.
Package has npm registry signatures but lacks cosign-verified SLSA attestations.
Use --require-provenance=false to proceed with signature-only verification
```

**Note:** OCI runner was already correct (only uses cosign for provenance).

