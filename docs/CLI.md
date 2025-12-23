# CLI Reference

This document provides a detailed reference for the `mcptrust` CLI.

**Note**: For commands that execute a subprocess (scan, lock, diff, policy check), you must separate the server command with `--`.

## Global Flags

| Flag | Description |
| :--- | :--- |
| `-h, --help` | help for mcptrust |
| `-v, --version` | version for mcptrust |

## Commands

### `scan`
Scan connects to an MCP server, interrogates it for capabilities, and outputs a security report in JSON format.

```bash
mcptrust scan -- <command> [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-h, --help` | | help for scan |
| `-p, --pretty` | `false` | Pretty print JSON output |
| `-t, --timeout` | `10s` | Timeout for MCP operations |

**Example**
```bash
mcptrust scan -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
mcptrust scan -- "python mcp_server.py"
```

---

### `lock`
Lock scans an MCP server and creates a lockfile (`mcp-lock.json`) that captures the current state of all tools with their capability hashes.

This lockfile serves as a "Safety Anchor" - if the server's capabilities change in the future, mcptrust can detect the drift and alert you.

```bash
mcptrust lock -- <command> [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-f, --force` | `false` | Overwrite lockfile even if drift is detected |
| `-h, --help` | | help for lock |
| `-o, --output` | `"mcp-lock.json"` | Output path for the lockfile |
| `-t, --timeout` | `10s` | Timeout for MCP operations |

**Example**
```bash
mcptrust lock -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
mcptrust lock -- "python mcp_server.py"
```

---

### `diff`
Diff compares the current state of an MCP server against the saved `mcp-lock.json` lockfile and reports what has changed.

This is the "Semantic Translator" - it tells you exactly what changed in human-readable terms, not just raw JSON patches.

```bash
mcptrust diff -- <command> [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-h, --help` | | help for diff |
| `-l, --lockfile` | `"mcp-lock.json"` | Path to the lockfile |
| `-t, --timeout` | `10s` | Timeout for MCP operations |

**Example**
```bash
mcptrust diff -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
mcptrust diff -- "python mcp_server.py"
```

---

### `policy check`
Check an MCP server's capabilities against security policies defined in a YAML file.

Policies use CEL (Common Expression Language) to define rules that are evaluated against the scan report. The 'input' variable provides access to the scan data.

```bash
mcptrust policy check -- <command> [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-h, --help` | | help for check |
| `-P, --policy` | (Internal Default) | Path to policy YAML file (uses default policy if not provided) |
| `-t, --timeout` | `10s` | Timeout for MCP operations |

**Example**
```bash
mcptrust policy check --policy ./policy.yaml -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
mcptrust policy check -- "python mcp_server.py"
```

---

### `bundle export`
Export the signed lockfile and security artifacts to a deterministic ZIP bundle.

This creates a reproducible bundle containing:
*   `manifest.json` (Bundle metadata with file hashes)
*   `mcp-lock.json` (Required - lockfile)
*   `mcp-lock.json.sig` (Required - signature)
*   `public.key` (Optional, if present)
*   `policy.yaml` (Optional, if present)
*   `README.txt` (Generated list of approved tools)

The bundle is fully deterministic - identical inputs produce identical outputs.
The lockfile must be signed before bundling. Use `mcptrust sign` first.

```bash
mcptrust bundle export [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-h, --help` | | help for export |
| `-l, --lockfile` | `"mcp-lock.json"` | Path to the lockfile |
| `-o, --output` | `"approval.zip"` | Path for the output ZIP file |
| `-s, --signature` | `"mcp-lock.json.sig"` | Path to the signature file |

**Example**
```bash
mcptrust bundle export --output approval.zip
mcptrust bundle export -o release-artifacts.zip
```

---

### `keygen`
Generate a new Ed25519 keypair for signing mcp-lock.json files.

This creates two files:
*   `private.key`: Keep this secret! Used to sign lockfiles.
*   `public.key`: Share this with your team to verify signatures.

```bash
mcptrust keygen [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-h, --help` | | help for keygen |
| `--private` | `"private.key"` | Path for the private key file |
| `--public` | `"public.key"` | Path for the public key file |

**Example**
```bash
mcptrust keygen
mcptrust keygen --private my-private.key --public my-public.key
```

---

### `sign`
Sign the `mcp-lock.json` lockfile using Ed25519 private key or Sigstore keyless signing.

Supports two modes:
- **Ed25519** (default): Sign with a private key file
- **Sigstore keyless** (`--sigstore`): Sign using OIDC identity (GitHub Actions, etc.)

The signature is computed over the canonical (deterministic) JSON representation of the lockfile, ensuring consistent verification.

```bash
mcptrust sign [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--canonicalization` | `"v1"` | Canonicalization version (v1 or v2) |
| `-h, --help` | | help for sign |
| `-k, --key` | `"private.key"` | Path to the private key (Ed25519 mode) |
| `-l, --lockfile` | `"mcp-lock.json"` | Path to the lockfile to sign |
| `-o, --output` | `"<lockfile>.sig"` | Path for the signature file |
| `--sigstore` | `false` | Use Sigstore keyless signing (requires cosign) |
| `--bundle-out` | | Also write raw Sigstore bundle to this path |

**Examples**
```bash
# Ed25519 signing
mcptrust sign --key private.key

# Sigstore keyless signing (CI/CD)
mcptrust sign --sigstore

# Custom lockfile
mcptrust sign --sigstore --lockfile custom-lock.json
```

---

### `verify`
Verify that the `mcp-lock.json` lockfile matches its signature.

The signature type is auto-detected:
- **Ed25519**: Requires `--key` flag
- **Sigstore**: Requires `--issuer` and `--identity` (or `--identity-regexp`)

Returns exit code 0 if valid, 1 if verification fails.

```bash
mcptrust verify [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-h, --help` | | help for verify |
| `-k, --key` | `"public.key"` | Path to the public key (Ed25519 mode) |
| `-l, --lockfile` | `"mcp-lock.json"` | Path to the lockfile to verify |
| `-s, --signature` | `"<lockfile>.sig"` | Path to the signature file |
| `--issuer` | | Expected OIDC issuer for Sigstore verification |
| `--identity` | | Expected certificate identity (SAN) for Sigstore |
| `--identity-regexp` | | Regexp pattern for certificate identity |
| `--github-actions` | `false` | Preset: use GitHub Actions OIDC issuer |

**Examples**
```bash
# Ed25519 verification
mcptrust verify --key public.key

# Sigstore verification (GitHub Actions signed)
mcptrust verify mcp-lock.json \
  --issuer https://token.actions.githubusercontent.com \
  --identity "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main"

# Sigstore with identity regex (accept any branch)
mcptrust verify mcp-lock.json \
  --github-actions \
  --identity-regexp "https://github.com/org/repo/.*"
```

---

### `proxy`
Run as stdio enforcement proxy between host and MCP server.

The proxy enforces v3 lockfile allowlists at runtime:
- Filters tools/list, prompts/list, resources/templates/list to only show allowed items
- Blocks tools/call, prompts/get, resources/read for non-allowlisted items
- Runs preflight drift detection before bridging traffic

```bash
mcptrust proxy [flags] -- <server-command> [server-args...]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--lock` | | Path to v3 lockfile (required) |
| `-t, --timeout` | `10s` | Server startup timeout |
| `--fail-on` | `critical` | Drift severity threshold: `critical`\|`moderate`\|`info` |
| `--policy` | | Policy preset name (optional) |
| `--audit-only` | `false` | Log blocked requests but allow traffic (no filtering) |
| `--filter-only` | `false` | Filter lists but don't block calls/reads |
| `--allow-static-resources` | `false` | Allow resources from startup resources/list |
| `--print-effective-allowlist` | `false` | Print derived allowlist and exit |

**Examples**
```bash
# Enforce mode (default)
mcptrust proxy --lock mcp-lock.json -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Audit-only mode (log but don't block)
mcptrust proxy --audit-only --lock mcp-lock.json -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Filter-only mode (filter lists, don't block calls)
mcptrust proxy --filter-only --lock mcp-lock.json -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

---

### `run`
Execute an MCP server from a verified artifact.

This command ensures the executed artifact matches the pinned artifact, preventing the registry from serving unverified code.

Workflow:
1. Download artifact
2. Verify integrity
3. Verify provenance (unless disabled)
4. Install from verified local tarball
5. Execute binary directly

```bash
mcptrust run --lock <lockfile> [-- <command>]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--lock` | | Path to lockfile (required) |
| `-t, --timeout` | `0` | Execution timeout (0 = no timeout) |
| `--dry-run` | `false` | Verify everything but don't execute |
| `--require-provenance` | `true` | Require provenance verification |
| `--expected-source` | | Expected source repository pattern (regex) |
| `--bin` | | Binary name for packages with multiple exports |
| `--keep-temp` | `false` | Don't delete temp directory (debug) |
| `--allow-missing-installed-integrity` | `false` | Proceed with warning if installed integrity cannot be verified (NOT recommended) |
| `--unsafe-allow-private-tarball-hosts` | `false` | Allow tarball downloads from private networks (NOT recommended) |

**Examples**
```bash
# Use command from lockfile
mcptrust run --lock mcp-lock.json

# Override command (must match pinned artifact)
mcptrust run --lock mcp-lock.json -- "npx -y @scope/pkg /custom/path"

# Dry run - verify everything but don't execute
mcptrust run --dry-run --lock mcp-lock.json

# Bypass provenance check (NOT recommended)
mcptrust run --require-provenance=false --lock mcp-lock.json
```

---

### `artifact`
Artifact verification commands.

#### `artifact verify`
Verify artifact integrity by comparing registry metadata against lockfile pin.

```bash
mcptrust artifact verify [lockfile] [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-l, --lockfile` | `mcp-lock.json` | Path to lockfile |
| `-t, --timeout` | `30s` | Timeout for registry operations |
| `--deep` | `false` | Download tarball and verify SHA256/SRI |
| `--unsafe-allow-private-tarball-hosts` | `false` | Allow tarball downloads from private networks (requires `--deep`) |

**Examples**
```bash
# Basic integrity check
mcptrust artifact verify

# Deep verification (download and verify tarball)
mcptrust artifact verify --deep mcp-lock.json
```

#### `artifact provenance`
Verify SLSA/Sigstore provenance attestations.

```bash
mcptrust artifact provenance [lockfile] [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-l, --lockfile` | `mcp-lock.json` | Path to lockfile |
| `-t, --timeout` | `60s` | Timeout for verification operations |
| `--expected-source` | | Expected source repository pattern (regex) |
| `--json` | `false` | Output as JSON |

**Examples**
```bash
# Verify provenance
mcptrust artifact provenance mcp-lock.json

# Verify with source repo check
mcptrust artifact provenance --expected-source "^https://github.com/modelcontextprotocol/.*" mcp-lock.json

# JSON output
mcptrust artifact provenance --json mcp-lock.json
```

---

### `completion`
Generate the autocompletion script for mcptrust for the specified shell.

```bash
mcptrust completion [command]
```

**Available Commands**
*   `bash`: Generate the autocompletion script for bash
*   `fish`: Generate the autocompletion script for fish
*   `powershell`: Generate the autocompletion script for powershell
*   `zsh`: Generate the autocompletion script for zsh

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-h, --help` | | help for completion |

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `drift detected` | Server capabilities don't match lockfile | Run `mcptrust check` to see diff, then `mcptrust lock` to approve |
| `signature verification failed` | Lockfile tampered or wrong key | Re-sign with `mcptrust sign` or check public key |
| `policy check failed` | Server violates CEL rules | Update server to comply or edit `policy.yaml` |
| `tarball host blocked` | Private IP detected (SSRF protection) | Use `--unsafe-allow-private-tarball-hosts` (if trust is established) |
