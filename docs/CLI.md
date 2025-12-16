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
Sign the `mcp-lock.json` lockfile using your Ed25519 private key.

This creates a signature file (`mcp-lock.json.sig`) that can be used to verify the lockfile hasn't been tampered with.

The signature is computed over the canonical (deterministic) JSON representation of the lockfile, ensuring consistent verification.

```bash
mcptrust sign [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--canonicalization` | `"v1"` | Canonicalization version (v1 or v2) |
| `-h, --help` | | help for sign |
| `-k, --key` | `"private.key"` | Path to the private key |
| `-l, --lockfile` | `"mcp-lock.json"` | Path to the lockfile to sign |
| `-o, --output` | `"mcp-lock.json.sig"` | Path for the signature file |

**Example**
```bash
mcptrust sign
mcptrust sign --lockfile custom-lock.json --key my-private.key
```

---

### `verify`
Verify that the `mcp-lock.json` lockfile matches its signature.

This checks that the lockfile hasn't been tampered with since it was signed.
Returns exit code 0 if valid, 1 if verification fails.

```bash
mcptrust verify [flags]
```

**Flags**

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-h, --help` | | help for verify |
| `-k, --key` | `"public.key"` | Path to the public key |
| `-l, --lockfile` | `"mcp-lock.json"` | Path to the lockfile to verify |
| `-s, --signature` | `"mcp-lock.json.sig"` | Path to the signature file |

**Example**
```bash
mcptrust verify
mcptrust verify --lockfile custom-lock.json --signature custom.sig --key my-public.key
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
