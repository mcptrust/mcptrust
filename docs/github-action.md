# MCPTrust GitHub Action

A minimal, reliable GitHub Action for running MCPTrust in CI/CD pipelines.

## Quick Start

Add to your workflow in 3 lines:

```yaml
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.6.0
- uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1
  with:
    mode: check
    server_command: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
```

> [!TIP]
> For production, pin to a tag or commit SHA instead of `@main`:
> `mcptrust/mcptrust/.github/actions/mcptrust@v0.1.1`

## Modes

| Mode | Purpose | Commands Executed |
|------|---------|-------------------|
| `lock` | Create/update lockfile | `mcptrust lock` |
| `check` | Verify server against lockfile | `mcptrust diff` + `mcptrust policy check` |

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `mode` | `check` | Operation mode: `lock` or `check` |
| `server_command` | (empty) | MCP server command (shell-parsed). Use `server_argv` for safer parsing. |
| `server_argv` | (empty) | MCP server command as multiline argv (one token per line). Safer than `server_command`. |
| `lockfile` | `mcp-lock.json` | Path to lockfile |
| `preset` | `baseline` | Policy preset: `baseline` (warn) or `strict` (fail) |
| `pin` | `true` | Pin artifact coordinates in lock mode |
| `verify_provenance` | `false` | Verify SLSA provenance in lock mode |
| `receipt` | `.mcptrust/receipts.jsonl` | Receipt output path for audit |
| `receipt_mode` | `append` | Receipt write mode: `overwrite` or `append` |
| `log_format` | `jsonl` | Log format: `pretty` or `jsonl` |
| `log_level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `log_output` | `stderr` | Log destination: `stderr` or file path |
| `install_method` | `go-install` | Install method: `go-install` or `release` |
| `go_version` | `1.24.x` | Go version for `go-install` method |
| `install_ref` | `main` | Git ref for installation (tag, branch, SHA) |
| `mcptrust_bin` | (empty) | Path to pre-installed binary (skips install) |

> [!NOTE]
> Either `server_command` OR `server_argv` must be provided. Use `server_argv` for commands with special characters.

## Outputs

| Output | Description |
|--------|-------------|
| `lockfile_path` | Resolved path to lockfile |
| `receipt_path` | Path to receipt file |

## Server Command Options

### Simple: server_command (shell-parsed)

For simple commands without special characters:

```yaml
server_command: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
```

### Safe: server_argv (one token per line)

For commands with paths containing spaces, quotes, or other special characters:

```yaml
server_argv: |
  npx
  -y
  @modelcontextprotocol/server-filesystem
  /path/with spaces/data
```

This avoids shell parsing issues entirely. Each line becomes one argv element.

## Examples

### Minimal Check (Pull Request Guard)

```yaml
name: MCPTrust Check
on: [pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.6.0
      - uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1
        with:
          mode: check
          server_command: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
          preset: strict
```

### Lock with Artifact Upload

```yaml
name: MCPTrust Lock
on: [workflow_dispatch]
jobs:
  lock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.6.0
      - uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1
        id: mcptrust
        with:
          mode: lock
          server_command: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
          pin: 'true'
          verify_provenance: 'true'
      
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.0
        with:
          name: mcptrust-artifacts
          path: |
            ${{ steps.mcptrust.outputs.lockfile_path }}
            ${{ steps.mcptrust.outputs.receipt_path }}
```

### Safe Command with Spaces

```yaml
- uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1
  with:
    mode: check
    server_argv: |
      npx
      -y
      @modelcontextprotocol/server-filesystem
      /path/with spaces/data
```

### Pinning to Specific Version (Production)

For reproducibility, pin both the action ref AND the install ref:

```yaml
# Pin to tag (recommended)
- uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1
  with:
    mode: check
    server_command: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
    install_ref: 'v0.1.1'

# Pin to commit SHA (most reproducible)
- uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53
  with:
    mode: check
    server_command: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
    install_ref: 'b020fc206b0b45c51209f4a7e9e1172a8f412f53' # Commit SHA
```

### Private Fork (go-install from source)

```yaml
- uses: your-org/mcptrust-fork/.github/actions/mcptrust@<SHA>
  with:
    mode: check
    server_command: 'npx -y @your-org/mcp-server /tmp'
    install_method: go-install
    install_ref: 'your-feature-branch'
```

## Full Example Workflow

For a comprehensive workflow with PR comments and advanced features, see:
[lock-and-check.yml](../examples/github-actions/lock-and-check.yml)

## Exit Codes

| Mode | Exit 0 | Exit 1 |
|------|--------|--------|
| `lock` | Lockfile created/updated | Lock failed |
| `check` | No drift, policy passed | Drift detected or policy failed |

## Troubleshooting

### "go install" fails

Ensure Go is not already set up with an incompatible version. The action uses `actions/setup-go@v5`.

### Lockfile not found (check mode)

Ensure you run `mode: lock` first or commit the lockfile to your repository.

### Command parsing issues

If your server command contains spaces, quotes, or special characters, use `server_argv` instead of `server_command`:

```yaml
# Instead of this (may break):
server_command: 'npx -y @mcp/server "/path with spaces"'

# Use this:
server_argv: |
  npx
  -y
  @mcp/server
  /path with spaces
```

### Provenance verification fails

SLSA provenance requires `cosign >= 2.4.1`. Install cosign before running:

```yaml
- uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da # v3.7.0
- uses: mcptrust/mcptrust/.github/actions/mcptrust@b020fc206b0b45c51209f4a7e9e1172a8f412f53 # v0.1.1
  with:
    mode: lock
    verify_provenance: 'true'
    server_command: '...'
```
