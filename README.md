# MCPTrust

**Deny-by-default runtime proxy + CI gate for MCP servers.**  
Pin what you run. Verify provenance. Enforce what tools/prompts/resources are allowed.

**For:** Teams running MCP servers in Claude Desktop, LangChain, AutoGen, CrewAI, or internal AI agents.

---

## What It Blocks

> **MCPTrust is the firewall between your AI agent and the MCP server.**

- 🚫 **Shadow tools at runtime** — Server adds a new `exec_shell` tool after you approved it? Blocked.
- 🚫 **Drift after lockfile** — Server changed since last CI check? Fails the build.
- 🚫 **Supply-chain swaps** — Tarball hash doesn't match pinned artifact? Execution denied.

Without MCPTrust, any MCP server can silently add dangerous capabilities. With MCPTrust, it's deny-by-default.

---

## 2-Minute Quickstart

```bash
# 1. Install
go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest

# 2. Lock the server's capabilities
mcptrust lock -- "npx -y @modelcontextprotocol/server-filesystem /tmp"

# 3. Run with enforcement (blocks anything not in lockfile)
mcptrust proxy --lock mcp-lock.json -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

**That's it.** The proxy now sits between your host and the server, blocking any tool/prompt/resource not in your lockfile.

---

## Try the "Fail Closed" Demo

See MCPTrust block a rogue tool in real-time:

```bash
# Lock a server
mcptrust lock -- "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Now imagine the server adds a new tool after you locked it...
# The proxy blocks unknown tools and logs:

mcptrust proxy --lock mcp-lock.json -- npx -y @modelcontextprotocol/server-filesystem /tmp
# → [BLOCKED] tools/call: unknown tool "exec_shell" not in allowlist
```

**Expected output when a tool is blocked:**
```
mcptrust: action=blocked method=tools/call tool=exec_shell reason="not in allowlist"
```

---

## How It Works

```
┌──────────┐      ┌─────────────────────┐      ┌────────────┐
│   Host   │ ──── │   mcptrust proxy    │ ──── │ MCP Server │
│ (Claude) │      │                     │      │            │
└──────────┘      └─────────────────────┘      └────────────┘
                          │
                          ▼
              ┌─────────────────────────────┐
              │  • ID translation (anti-    │
              │    spoofing, server never   │
              │    sees host request IDs)   │
              │  • List filtering           │
              │  • Call/read blocking       │
              │  • Drift preflight check    │
              │  • Audit logs/receipts      │
              └─────────────────────────────┘
```

---

## Feature Grid

| Feature | What It Does |
|---------|--------------|
| **Runtime proxy** | Deny-by-default enforcement between host and server |
| **Lockfile v3** | Allowlist tools, prompts, resources, templates |
| **Drift detection** | CI fails on critical/moderate/info changes |
| **Policy presets** | `baseline` (warn) or `strict` (fail-closed) |
| **Artifact pinning** | SHA-512/256 integrity + provenance verification |
| **ID translation** | Anti-spoofing: server never sees real host IDs |
| **Audit-only mode** | Log everything, block nothing (training/rollout) |
| **Filter-only mode** | Filter lists, don't block calls (visibility) |

---

## Trust & Security Guarantees

MCPTrust makes explicit guarantees that other tools don't:

| Invariant | Mechanism |
|-----------|-----------|
| **Server never sees host request IDs** | Proxy-generated IDs; host IDs never forwarded |
| **Unknown/duplicate responses dropped** | Anti-spoofing: responses must match pending requests |
| **Fail-closed on pending saturation** | If tracking table is full, deny (no silent pass) |
| **Fail-closed on RNG failure** | If ID generation fails, deny the request |
| **Fail-closed on checksum mismatch** | Artifact hash must match or execution denied |
| **NDJSON line limits** | Lines > 10MB dropped (OOM defense) |
| **HTTPS-only tarball downloads** | HTTP blocked; private IPs blocked (SSRF defense) |
| **CI action pinned to SHA** | Composite action uses pinned dependencies |

See [SECURITY_GUARANTEES.md](SECURITY_GUARANTEES.md) for full details.

---

## Integrations

MCPTrust works with your existing stack:

| Platform | Status | Notes |
|----------|--------|-------|
| **Claude Desktop** | ✅ Works | Point `mcpServers` to `mcptrust proxy -- <server>` |
| **Claude Code** | ✅ Works | Use `claude mcp add` with mcptrust proxy |
| **Node MCP servers** | ✅ Works | Any stdio-based server (npx, node, etc.) |
| **Python agents** | ✅ Works | LangChain, AutoGen, CrewAI — use proxy as subprocess |
| **GitHub Actions** | ✅ Native | [Composite action](.github/actions/mcptrust) for CI gates |
| **Docker** | ✅ Works | `mcptrust run` supports `docker run IMAGE` |

### Claude Desktop Example

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcptrust",
      "args": ["proxy", "--lock", "/path/to/mcp-lock.json", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

### Claude Code Example

```bash
# Generate lockfile
mcptrust lock --v3 -- npx @modelcontextprotocol/server-filesystem /tmp

# Add MCP server with MCPTrust proxy
claude mcp add my-server -- mcptrust proxy --lock mcp-lock.json -- npx @modelcontextprotocol/server-filesystem /tmp
```

---

## GitHub Action (CI Gate)

Add MCPTrust to your CI in 30 seconds:

```yaml
- uses: mcptrust/mcptrust/.github/actions/mcptrust@<SHA>
  with:
    mode: check
    lockfile: mcp-lock.json
    fail_on: critical
    policy: baseline
    server_command: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
```

| Mode | Purpose |
|------|---------|
| `lock` | Generate lockfile from server |
| `check` | Fail if drift detected |
| `policy` | Enforce CEL governance rules |

> [!TIP]
> Pin to a commit SHA for security tooling. See [Action README](.github/actions/mcptrust/README.md).

---

## Proxy Modes

```
                          ┌─────────────────────────────┐
                          │        Proxy Modes          │
                          └─────────────────────────────┘
                                       │
           ┌───────────────────────────┼───────────────────────────┐
           │                           │                           │
           ▼                           ▼                           ▼
   ┌───────────────┐          ┌───────────────┐         ┌────────────────┐
   │    ENFORCE    │          │  FILTER-ONLY  │         │  AUDIT-ONLY    │
   │   (default)   │          │               │         │                │
   ├───────────────┤          ├───────────────┤         ├────────────────┤
   │ ✅ Filter lists│         │ ✅ Filter lists│         │ ❌ No filtering│
   │ ✅ Block calls │         │ ❌ Allow calls │         │ ❌ Allow calls │
   ├───────────────┤          ├───────────────┤         ├───────────── ──┤
   │  Production   │          │    Rollout    │         │   Training     │
   └───────────────┘          └───────────────┘         └────────────────┘
```

| Mode | Lists Filtered | Calls Blocked | Use Case |
|------|----------------|---------------|----------|
| `enforce` (default) | ✅ | ✅ | Production |
| `--filter-only` | ✅ | ❌ | Visibility rollout |
| `--audit-only` | ❌ | ❌ | Training/logging |

```bash
# Enforce mode (default) — blocks unknown tools
mcptrust proxy --lock mcp-lock.json -- npx -y ...

# Audit-only — log but don't block (safe for rollout)
mcptrust proxy --audit-only --lock mcp-lock.json -- npx -y ...

# Filter-only — filter lists, don't block calls
mcptrust proxy --filter-only --lock mcp-lock.json -- npx -y ...
```

---

## Supply Chain Security

MCPTrust pins and verifies the exact artifact you run:

```bash
# Lock with artifact pinning + provenance
mcptrust lock --pin --verify-provenance -- "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Enforced execution (verifies everything, then runs)
mcptrust run --lock mcp-lock.json
```

| Guarantee | Mechanism |
|-----------|-----------|
| Tarball SHA-512 matches | `lockfile.artifact.integrity` |
| Tarball SHA-256 matches | `lockfile.artifact.tarball_sha256` |
| SLSA provenance verified | cosign attestation validation |
| No postinstall scripts | `--ignore-scripts` enforced |
| Local execution only | Binary from verified `node_modules/.bin/` |

---

## Security Posture

MCPTrust's own supply chain is hardened:

- ✅ **GitHub Actions pinned to SHAs** — All action dependencies use commit SHAs
- ✅ **Dependabot enabled** — Automated updates for GitHub Actions
- ✅ **Release checksums fail-closed** — Binary verification required
- ✅ **HTTPS-only downloads** — HTTP and private IPs blocked
- ✅ **Responsible disclosure** — See [SECURITY.md](SECURITY.md)

---

## CLI Reference

| Command | Purpose |
|---------|---------|
| `scan` | Inspect MCP server capabilities |
| `lock` | Create `mcp-lock.json` from server state |
| `diff` | Detect drift between lockfile and live server |
| `proxy` | Run as stdio enforcement proxy |
| `run` | Verified execution from pinned artifact |
| `sign` / `verify` | Ed25519 or Sigstore signatures |
| `policy check` | Enforce CEL governance rules |
| `bundle export` | Create deterministic ZIP for distribution |

See [docs/CLI.md](docs/CLI.md) for full reference.

---

## Signing & Verification

### Ed25519 (Local)

```bash
mcptrust keygen                           # Generate keypair
mcptrust sign --key private.key mcp-lock.json
mcptrust verify --key public.key mcp-lock.json
```

### Sigstore (CI/CD, Keyless)

```bash
mcptrust sign --sigstore mcp-lock.json
mcptrust verify mcp-lock.json \
  --issuer https://token.actions.githubusercontent.com \
  --identity "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main"
```

See [docs/SIGSTORE.md](docs/SIGSTORE.md) for GitHub Actions examples.

---

## Observability

### Structured Logging

```bash
mcptrust lock --log-format jsonl --log-output /var/log/mcptrust.jsonl -- "..."
```

### Receipts (Audit Trail)

```bash
mcptrust lock --receipt /var/log/mcptrust/receipt.json -- "..."
```

### OpenTelemetry

```bash
mcptrust lock --otel --otel-endpoint localhost:4318 -- "..."
```

See [docs/observability-otel.md](docs/observability-otel.md) for full options.

---

## Documentation

- [CLI Reference](docs/CLI.md) — Commands, flags, examples
- [Claude Code Guide](docs/CLAUDE_CODE.md) — Full integration walkthrough
- [LangChain Guide](docs/LANGCHAIN.md) — Python adapter for agents
- [Sigstore Guide](docs/SIGSTORE.md) — Keyless signing for CI/CD
- [Security Guarantees](SECURITY_GUARANTEES.md) — Explicit security properties
- [Threat Model](docs/THREAT_MODEL.md) — What we protect against
- [Policy Guide](docs/POLICY.md) — Writing CEL rules
- [Migration Guide](docs/MIGRATION.md) — Version compatibility

---

## Roadmap

- 🔜 **Policy packs** — Shareable governance rule sets
- 🔜 **Receipts schema v2** — Stable schema for SIEM integration
- 🔜 **Resource/prompt template locking** — Full MCP surface coverage

---

## Limitations

MCPTrust secures the **interface**, not the **implementation**:

| Out of Scope | Why |
|--------------|----- |
| **Malicious logic** | A tool named `read_file` that runs `rm -rf` looks identical via schema |
| **Runtime prompt injection** | MCPTrust doesn't monitor agent ↔ tool conversations |
| **Key compromise** | If `private.key` is stolen, attacker can sign malicious lockfiles |
| **Development overhead** | For quick prototyping, the lockfile workflow may be overkill |

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for full details.

---

## Development

```bash
go test ./...                              # Unit tests
bash tests/gauntlet.sh                     # Integration suite
MCPTRUST_BIN=./mcptrust bash scripts/smoke.sh  # Smoke test
```

---

## Contributing

Issues and PRs welcome. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[Apache-2.0](LICENSE)
