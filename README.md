# MCPTrust

**Lockfile for MCP servers.** Secure AI agent tool discovery with cryptographic integrity.

## Why MCPTrust??

- **Integrity** — Ed25519 or Sigstore keyless signatures ensure your lockfile hasn't been tampered with
- **Drift Detection** — Know instantly when an MCP server's tools change
- **Governance** — Enforce security policies with CEL expressions

## Quickstart

### Ed25519 Demo (Local, No External Dependencies)

```bash
# Install
go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest
mcptrust --version  # verify installation

# 1. Lock the server's current state
mcptrust lock -- "npx -y @modelcontextprotocol/server-filesystem /tmp"

# 2. Generate keys and sign
mcptrust keygen
mcptrust sign --key private.key mcp-lock.json

# 3. Verify before each run
mcptrust verify --key public.key mcp-lock.json
```

### Sigstore Demo (CI/CD, Keyless)

For GitHub Actions—no private keys to manage:

```bash
# Sign using OIDC identity (requires cosign CLI)
mcptrust sign --sigstore mcp-lock.json

# Verify with identity constraints
mcptrust verify mcp-lock.json \
  --issuer https://token.actions.githubusercontent.com \
  --identity "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main"
```

> [!IMPORTANT]
> The `--identity` string **must exactly match** your workflow file path and Git ref:
> - Use `sign.yml` not `sign.yaml` (match your actual filename)
> - Use `refs/heads/main` not just `main`
> - The org/repo must match your repository

> [!NOTE]
> Sigstore v3 signatures cannot be verified by MCPTrust versions prior to this release.
> Upgrade MCPTrust in CI before switching. Ed25519 v1/v2 signatures remain supported.

See [docs/SIGSTORE.md](docs/SIGSTORE.md) for GitHub Actions workflow examples.


## CLI Commands

| Command | Purpose |
|---------|---------|
| `scan` | Inspect MCP server capabilities |
| `lock` | Create `mcp-lock.json` from server state |
| `diff` | Detect drift between lockfile and live server |
| `sign` / `verify` | Ed25519 or Sigstore signature operations |
| `policy check` | Enforce CEL governance rules |
| `bundle export` | Create deterministic ZIP for distribution |

> [!NOTE]
> Commands that connect to servers require `--` separator:
> `mcptrust diff -- "npx -y @modelcontextprotocol/server-filesystem /tmp"`

## What It Looks Like

**Drift Detection** — When the server changes after you locked it:

```
╔══════════════════════════════════════╗
║         CHANGES DETECTED             ║
╚══════════════════════════════════════╝

[~] list_directory
  • Documentation update: description has changed.
```

**Policy Failure** — When a tool violates governance rules:

```
Policy: Strict Policy

Results:
--------------------------------------------------
✗ Must be namespaced
  → All tools must start with 'myapp_' prefix
--------------------------------------------------

✗ Some policy checks failed
```

## Security Guarantees

| Guarantee | Mechanism | Tested By |
|-----------|-----------|-----------|
| Lockfile integrity | Ed25519 / Sigstore signatures | Tamper detection in gauntlet |
| Drift detection | SHA-256 hash comparison | Diff tests |
| Bundle reproducibility | Fixed timestamps + ordering | Hash comparison tests |

### Non-Goals

MCPTrust verifies the *interface* (schemas), not implementation. It does not protect against:
- Malicious logic inside tools (a `read_file` that actually deletes)
- Runtime prompt injection  
- Key compromise

> **Note**: v0.x locks **tool interfaces only**. Resources, prompts, and other MCP surfaces are not yet enforced.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for details.

## Documentation

- [CLI Reference](docs/CLI.md) — Commands, flags, and examples
- [Sigstore Guide](docs/SIGSTORE.md) — Keyless signing for CI/CD
- [Security Model](SECURITY_GUARANTEES.md) — What we guarantee
- [Migration Guide](docs/MIGRATION.md) — Canonicalization versions, backward compat
- [Policy Guide](docs/POLICY.md) — Writing CEL governance rules

## Development

```bash
# Run unit tests
go test ./...

# Run integration suite
bash tests/gauntlet.sh

# Quick smoke test (Ed25519 only, temp dir)
MCPTRUST_BIN=./mcptrust bash scripts/smoke.sh

# Fixture mode (no network)
MCPTRUST_FORCE_FIXTURE=1 bash tests/gauntlet.sh
```

### Security Disclaimers

> ⚠️ **Do not commit private keys.** Add `*.key` to `.gitignore`.

> ⚠️ **Sigstore transparency logs are public and immutable.** Your identity (email or workflow URI) is recorded permanently when signing.

> ⚠️ **v3 Sigstore signatures require MCPTrust upgrade** before enabling `--sigstore` in CI.

### Common Gotchas

| Issue | Cause | Fix |
|-------|-------|-----|
| Verify fails with "wrong identity" | Identity string doesn't match exactly | Check workflow filename (`sign.yml` not `sign.yaml`) and branch ref (`refs/heads/main` not `main`) |
| Verify fails with "wrong issuer" | Signed locally but verifying as GitHub Actions | Local signing uses your IdP (e.g., `accounts.google.com`), not `token.actions.githubusercontent.com` |
| "cosign not found" | cosign CLI not installed | `brew install cosign` or see [cosign docs](https://docs.sigstore.dev/cosign/installation/) |

## Contributing

Issues and PRs welcome. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[Apache-2.0](LICENSE)

