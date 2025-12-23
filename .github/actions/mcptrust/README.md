# MCPTrust GitHub Action

Composite action for locking and checking MCP server capabilities in CI/CD pipelines.

## Usage

```yaml
- uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1
  with:
    mode: check
    lockfile: mcp-lock.json
    fail_on: critical
    policy: baseline
    server_command: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
```

See the main [README](../../../README.md) for full documentation and examples.

---

## CI Safety Notes

### Pin to a Tag or SHA

Always pin security tooling to a specific version:

```yaml
# ✅ Good: pinned to SHA
- uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1

# ✅ Better: pinned to commit SHA (immutable)
- uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53

# ❌ Avoid: mutable branch reference
- uses: mcptrust/mcptrust/.github/actions/mcptrust@main
```

### Avoid `pull_request_target` with Untrusted Checkouts

The `pull_request_target` event runs with base branch privileges and may have access to secrets. Never checkout fork code before running security tooling:

```yaml
# ❌ DANGEROUS: checking out fork code with elevated privileges
on: pull_request_target
jobs:
  check:
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.6.0
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Fork code!
      - uses: ./.github/actions/mcptrust  # Runs fork's action!

# ✅ SAFE: use pull_request (runs on fork with fork privileges)
on: pull_request
jobs:
  check:
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.6.0
      - uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1
```

### Local vs Remote Action Usage

| Pattern | When Safe |
|---------|-----------|
| `uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53` | Always (action from trusted source) |
| `uses: ./.github/actions/mcptrust` | Only when checkout is trusted (not fork code) |

If using a local action (`uses: ./.github/actions/...`), the action code comes from the checkout. On `pull_request_target` with fork checkout, attackers control the action itself.

**Recommendation:** Use remote action references pinned to SHA for security-critical workflows.
