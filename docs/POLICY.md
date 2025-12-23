# Policy Guide

MCPTrust uses [CEL (Common Expression Language)](https://github.com/google/cel-spec) to define security policies.

> [!NOTE]
> **Regex Safety**: CEL's `matches()` function uses Go's RE2 engine, which guarantees linear-time matching. This means **no catastrophic backtracking** and **no ReDoS vulnerabilities** are possible, regardless of the input pattern or data size.


## Policy File Structure

A policy file is a YAML document with a list of rules.

```yaml
name: "My Policy"
rules:
  - name: "Rule Name"
    # CEL expression evaluated against 'input'
    expr: "expression" 
    failure_msg: "Message to show if false"
```

## The `input` Object

The `input` variable provides access to the scan report:

| Field | Type | Description |
|-------|------|-------------|
| `input.tools` | list | Tools discovered on server |
| `input.tools[].name` | string | Tool name |
| `input.tools[].description` | string | Tool description |
| `input.tools[].risk_level` | string | `"LOW"`, `"MEDIUM"`, or `"HIGH"` |
| `input.tools[].inputSchema` | map | JSON Schema for tool arguments |

### Supply Chain Fields (requires `--lockfile`)

When using `policy check --lockfile mcp-lock.json`, the following fields are also available:

#### `input.artifact`

| Field | Type | Description |
|-------|------|-------------|
| `input.artifact.type` | string | `"npm"` or `"oci"` |
| `input.artifact.name` | string | Package name (e.g., `"@scope/package"`) |
| `input.artifact.version` | string | Resolved version (e.g., `"1.2.3"`) |
| `input.artifact.registry` | string | Registry URL (npm only) |
| `input.artifact.integrity` | string | SHA-512 SRI hash (e.g., `"sha512-..."`) |
| `input.artifact.tarball_url` | string | Tarball download URL (npm only) |
| `input.artifact.tarball_sha256` | string | Tarball SHA-256 hash in hex (npm only) |
| `input.artifact.tarball_size` | int | Tarball size in bytes (npm only) |
| `input.artifact.image` | string | Image reference (OCI only) |
| `input.artifact.digest` | string | Image digest (OCI only) |

#### `input.provenance`

Available when artifact has verified SLSA provenance via cosign:

> [!IMPORTANT]
> `input.provenance` is **only populated when `method == "cosign_slsa"`**. When npm audit signatures fallback is used, provenance fields (source_repo, workflow_uri, builder_id) are empty and `input.provenance` is not included in the policy input. Policies relying on these fields will correctly fail when only npm signatures are available.

| Field | Type | Description |
|-------|------|-------------|
| `input.provenance.method` | string | `"cosign_slsa"` (always, when present) |
| `input.provenance.verified` | bool | `true` if attestation validated |
| `input.provenance.predicate_type` | string | SLSA predicate type URL |
| `input.provenance.builder_id` | string | Builder identity |
| `input.provenance.source_repo` | string | Source repository URL |
| `input.provenance.source_ref` | string | Git ref (e.g., `"refs/tags/v1.0.0"`) |
| `input.provenance.workflow_uri` | string | Workflow path (e.g., `".github/workflows/release.yml"`) |
| `input.provenance.issuer` | string | OIDC issuer |
| `input.provenance.identity` | string | Certificate identity |
| `input.provenance.verified_at` | string | Verification timestamp (RFC3339) |

> [!TIP]
> Use `has(input.artifact)` to check if artifact data exists before accessing fields.

**Fail-closed behavior**: Parse errors, missing fields, or unknown functions cause the policy check to fail.


### Shell Metacharacters
The runner enforces strict validation on command arguments to prevent shell injection and user confusion.
- **Backticks** are blocked globally (even inside quotes).
- Shell operators (`|`, `&`, `;`, etc.) are blocked outside of quotes.
- This ensures that `mcptrust run` behaves predictably and safely without invoking a shell.

## Examples

### Safe Starter Policy
Ensures the server exposes at least one tool and no obvious high-risk tools.

```yaml
name: "Safe Starter"
rules:
  - name: "Tools Exist"
    expr: "size(input.tools) > 0"
    failure_msg: "Server is empty."
    
  - name: "No High Risk"
    expr: "!input.tools.exists(t, t.risk_level == 'HIGH')"
    failure_msg: "High-risk tools are not allowed."
```

### Strict Policy (Denylist)
Block known dangerous tools by name.

```yaml
name: "Strict Denylist"
rules:
  - name: "No Dangerous Tools"
    expr: "!input.tools.exists(t, t.name in ['exec', 'shell', 'eval', 'run_command'])"
    failure_msg: "Dangerous tool detected."

  - name: "Approved Prefix"
    expr: "input.tools.all(t, t.name.startsWith('my_service_'))"
    failure_msg: "Tools must be namespaced with 'my_service_'."

  - name: "Argument Limit"
    expr: "input.tools.all(t, size(t.inputSchema.properties) <= 5)"
    failure_msg: "Tools cannot have more than 5 arguments."
```

### Supply Chain Policies

When using `--lockfile` with `policy check`, artifact and provenance fields are available. These examples enforce trusted sources and approved build workflows.

> [!TIP]
> Always use `input.provenance.method == "cosign_slsa"` to verify true SLSA provenance. While `has(input.provenance)` currently implies cosign verification, the explicit method check is future-proof if npm fallback metadata is ever exposed.

#### Trusted Repository

Ensure the artifact comes from a known GitHub organization:

```yaml
name: "Trusted Repository"
rules:
  - name: "from_trusted_org"
    expr: |
      has(input.provenance) && 
      input.provenance.method == "cosign_slsa" &&
      input.provenance.source_repo.matches("^https://github.com/(modelcontextprotocol|myorg)/.*")
    failure_msg: "Artifact must come from a trusted GitHub organization"
```

#### Approved Workflow

Ensure the artifact was built by an approved CI workflow:

```yaml
name: "Approved Workflow"
rules:
  - name: "approved_build_workflow"
    expr: |
      has(input.provenance) && 
      input.provenance.method == "cosign_slsa" &&
      input.provenance.workflow_uri in [
        ".github/workflows/release.yml",
        ".github/workflows/publish.yml"
      ]
    failure_msg: "Artifact must be built by an approved release workflow"
```

#### Combined Supply Chain Policy

Full supply chain verification policy combining pinning, provenance, and source validation:

```yaml
name: "Production Supply Chain"
rules:
  - name: "artifact_pinned"
    expr: 'has(input.artifact) && input.artifact.integrity != ""'
    failure_msg: "Artifact must be pinned with integrity hash"
    severity: error
    
  - name: "slsa_provenance_verified"
    expr: 'has(input.provenance) && input.provenance.method == "cosign_slsa"'
    failure_msg: "Artifact must have verified SLSA provenance (cosign)"
    severity: error
    
  - name: "trusted_source"
    expr: |
      has(input.provenance) && 
      input.provenance.source_repo.matches("^https://github.com/modelcontextprotocol/.*")
    failure_msg: "Artifact must come from modelcontextprotocol GitHub org"
    severity: error
```

## Troubleshooting

### "CEL compile error"

Your expression has a syntax error. Check:
- String literals use single quotes: `'HIGH'` not `"HIGH"`
- Field names match exactly (case-sensitive)
- Parentheses are balanced

### "no such field"

The field doesn't exist in the input. Common causes:
- `input.artifact` requires `--lockfile` flag
- `input.provenance` requires artifact with verified provenance

### "policy check failed" with baseline preset

Baseline uses `warn` severity, so it should exit 0 with warnings. If it fails with exit 1, check for rules with `severity: error`.

### No cosign or npm installed

Provenance verification requires either:
- **cosign** (recommended): `brew install cosign` or see [sigstore docs](https://docs.sigstore.dev/cosign/installation/)
- **npm ≥9.5**: `npm audit signatures` fallback

If neither is available, `--verify-provenance` will fail with a clear error.

### No SLSA provenance attestation found

Not all packages have SLSA provenance. Check:
1. Package is published via GitHub Actions with npm provenance enabled
2. Package version is recent enough to have attestations
3. Use `npm view <package> --json | jq '.attestations'` to check

### Source repository mismatch

When using `--expected-source`, the error shows actual vs expected:
```
source repo mismatch: got "https://github.com/other/repo", expected pattern "^https://github.com/trusted/"
```
Update your policy or verify the package source is correct.

### Strict preset failed

When strict preset fails:
1. Check which rule failed in the output
2. If `artifact_pinned_required`: Run `mcptrust lock --pin`
3. If `provenance_required`: Add `--verify-provenance` (requires package with attestations)
4. If `no_high_risk_tools`: Review the flagged tools for approval

### Integrity mismatch error

```
integrity mismatch (pinned vs installed):
  expected: sha512-abc123...
  actual:   sha512-def456...
```

This means the installed package doesn't match the lockfile pin. Possible causes:
- Package republished with same version (rare, npm immutability should prevent)
- Lockfile was created with a different version
- Registry served different content

**Fix**: Re-run `mcptrust lock --pin` to update the lockfile.

### tarball_sha256 mismatch

```
sha256 mismatch (pinned vs computed tarball):
  expected: abc123...
  actual:   def456...
```

The downloaded tarball's SHA-256 doesn't match the pinned value. Possible causes:
- The tarball bytes on the registry have changed since pinning
- Lockfile was edited or corrupted
- Different registry mirror serving different content

**Fix**: Re-run `mcptrust lock --pin --verify-provenance` to update the lockfile.

### tarball_url 404

If the pinned `tarball_url` returns 404, the runner falls back to fetching the tarball URL from registry metadata for the pinned name/version. This maintains compatibility with registry URL changes while still verifying integrity. If both fail, ensure:
- The package version still exists in the registry
- Network connectivity to the registry is available
- The registry URL in the lockfile is correct


### Multi-bin package error

```
package exports multiple binaries (cli, server, tools); use --bin <name> to choose one
```

The package has multiple executable exports. Specify which one to run:

```bash
mcptrust run --lock mcp-lock.json --bin server
```

### Unsupported docker command

```
unsupported docker command: only 'docker run' is supported; got 'docker compose'
```

Runner mode supports `docker run [OPTIONS] IMAGE [CMD]` only. Not supported:
- `docker compose` / `docker-compose`
- `docker exec`
- Shell pipelines

Use explicit `docker run` commands with digest-pinned images.

## Pairing Policy Presets with Runner Mode

For full supply chain enforcement, combine policy checks with `mcptrust run`:

```bash
# 1. Verify against strict preset
mcptrust policy check --preset strict --lockfile mcp-lock.json -- "$SERVER_CMD"

# 2. Execute from verified local artifact (not from registry)
mcptrust run --lock mcp-lock.json
```

This ensures:
- **Policy check** validates governance rules (pinning, provenance, tool restrictions)
- **Runner mode** enforces that the executed artifact matches the pinned artifact

> [!TIP]
> Chain the commands in CI:
> ```bash
> mcptrust policy check --preset strict --lockfile mcp-lock.json -- "$CMD" && \
> mcptrust run --lock mcp-lock.json
> ```

## Network Security

All tarball downloads use a unified hardened downloader (`internal/netutil`) to prevent SSRF and DNS rebinding attacks.

### Protections Enabled

| Protection | Description |
|------------|-------------|
| HTTPS only | HTTP URLs are rejected |
| Redirect validation | Up to 5 redirects allowed, each hop validated (no scheme downgrade) |
| DNS rebinding defense | Resolved IPs are checked at connect time |
| Private IP blocking | localhost, 127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, CGNAT, TEST-NETs blocked |
| IPv6 protection | ::1, fc00::/7, fe80::/10 blocked |
| No proxy | Proxy is disabled by default |

### Troubleshooting Network Errors

#### "tarball host blocked (private/reserved)"

Your tarball URL points to a private IP address (e.g., 10.x.x.x, 192.168.x.x).
This is blocked by default to prevent SSRF attacks.

**If you have a private npm registry**, use `--unsafe-allow-private-tarball-hosts`:

```bash
mcptrust run --unsafe-allow-private-tarball-hosts --lock mcp-lock.json
mcptrust artifact verify --deep --unsafe-allow-private-tarball-hosts mcp-lock.json
```

> [!CAUTION]
> This flag disables SSRF protection against private IP addresses.
> Only use if your registry is on a trusted private network.
> HTTPS, redirect validation, and hash verification remain enforced.

#### "redirect blocked / redirect validation failed"

A tarball redirect URL failed security validation. This can happen if:
- Redirect target uses HTTP (scheme downgrade blocked)
- Redirect target points to a private IP
- Too many redirects (>5)

Check your registry configuration or CDN setup.

#### "DNS resolved to private/reserved IP address"

DNS rebinding attack prevention. Your hostname resolved to a private IP at connect time.
This is blocked even if the URL hostname looks public.

Check if you have a split-horizon DNS or local DNS override pointing public hostnames to private IPs.

### 404 Fallback Behavior

If the pinned `tarball_url` returns 404 or a network error:
1. A warning is printed to stderr
2. The tarball URL is fetched fresh from registry metadata
3. The fallback URL is validated with the same security rules
4. If download succeeds, **hashes are still verified** (integrity is the real gate)

This ensures availability while maintaining security.
