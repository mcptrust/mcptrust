# MCPTrust

**Lockfile for MCP servers.** Secure AI agent tool discovery with cryptographic integrity.

## Why MCPTrust?

- **Integrity** — Ed25519 signatures ensure your lockfile hasn't been tampered with
- **Drift Detection** — Know instantly when an MCP server's tools change
- **Governance** — Enforce security policies with CEL expressions

## Quickstart

```bash
# Install
go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest

# 1. Lock the server's current state
mcptrust lock -- "npx -y @modelcontextprotocol/server-filesystem /tmp"

# 2. Generate keys and sign
mcptrust keygen
mcptrust sign --key private.key

# 3. Verify before each run
mcptrust verify --key public.key
```

## CLI Commands

| Command | Purpose |
|---------|---------|
| `scan` | Inspect MCP server capabilities |
| `lock` | Create `mcp-lock.json` from server state |
| `diff` | Detect drift between lockfile and live server |
| `sign` / `verify` | Ed25519 signature operations |
| `policy check` | Enforce CEL governance rules |
| `bundle export` | Create deterministic ZIP for distribution |

> [!NOTE]
> Commands that connect to servers require `--` separator:
> `mcptrust diff -- "npx -y @modelcontextprotocol/server-filesystem /tmp"`

## Security Guarantees

| Guarantee | Mechanism | Tested By |
|-----------|-----------|-----------|
| Lockfile integrity | Ed25519 signatures | Tamper detection in gauntlet |
| Drift detection | SHA-256 hash comparison | Diff tests |
| Bundle reproducibility | Fixed timestamps + ordering | Hash comparison tests |

### Non-Goals

MCPTrust verifies the *interface* (schemas), not implementation. It does not protect against:
- Malicious logic inside tools (a `read_file` that actually deletes)
- Runtime prompt injection  
- Key compromise

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for details.

## Documentation

- [CLI Reference](docs/CLI.md) — Commands, flags, and examples
- [Security Model](SECURITY_GUARANTEES.md) — What we guarantee
- [Migration Guide](docs/MIGRATION.md) — Canonicalization versions, backward compat
- [Policy Guide](docs/POLICY.md) — Writing CEL governance rules

## Development

```bash
# Run unit tests
go test ./...

# Run integration suite
bash tests/gauntlet.sh

# Fixture mode (no network)
MCPTRUST_FORCE_FIXTURE=1 bash tests/gauntlet.sh
```

## Contributing

Issues and PRs welcome. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE)
