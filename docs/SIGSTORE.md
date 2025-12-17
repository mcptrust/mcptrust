# Sigstore Keyless Signing

MCPTrust supports **Sigstore keyless signing** for CI/CD workflows that don't want to manage private keys.

> [!WARNING]
> **Enabling `--sigstore` introduces v3 signatures that older MCPTrust versions cannot verify.**
> Upgrade MCPTrust in CI before switching to Sigstore signing.
> Ed25519 v1/v2 signatures remain fully supported for backward compatibility.

## What is Keyless Signing?

With Sigstore's keyless signing:
- **No private keys to manage** — authentication uses OIDC (OpenID Connect)
- **Identity from your CI/CD** — GitHub Actions, GitLab CI, etc. provide the identity
- **Transparency log** — signatures are recorded in Rekor for auditability

## When to Use

| Mode | Use Case |
|------|----------|
| **Ed25519** | Team-controlled signing, offline environments, custom workflows |
| **Sigstore** | CI/CD automation, GitHub Actions, GitLab CI, no secrets management |

## Requirements

- **cosign CLI** must be installed: https://docs.sigstore.dev/cosign/installation/
- **Minimum version**: cosign v2.0+ recommended (bundle format compatibility)
- For CI: OIDC token provider (GitHub Actions `id-token: write` permission)

## Canonicalization

When signing with Sigstore, MCPTrust always signs **canonical bytes** produced by `Canonicalize(lockfile, canon_version)`.

- `canon_version=v1` (default): The project's original canonical JSON (sorted keys, no extra whitespace)
- `canon_version=v2`: JCS (RFC 8785) canonicalization

**Why canonicalize?** This prevents false verification failures from key ordering or whitespace differences between JSON serializers.

The `canon_version` is stored in the signature header and MUST be present for Sigstore signatures to verify.

## GitHub Actions Workflow

### Signing Lockfile

```yaml
name: Sign Lockfile

on:
  push:
    branches: [main]

permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: sigstore/cosign-installer@v3.7.0
        with:
          cosign-release: 'v2.4.1'
      
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      
      - run: go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest
      
      - name: Sign lockfile (keyless)
        run: mcptrust sign --sigstore mcp-lock.json
      
      - name: Commit signature
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add mcp-lock.json.sig
          git commit -m "Update lockfile signature [skip ci]" || echo "No changes"
          git push
```

### Verifying on Pull Requests

```yaml
name: Verify Lockfile

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: sigstore/cosign-installer@v3.7.0
      
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      
      - run: go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest
      
      - name: Verify lockfile signature
        run: |
          mcptrust verify mcp-lock.json \
            --issuer https://token.actions.githubusercontent.com \
            --identity "https://github.com/${{ github.repository }}/.github/workflows/sign.yml@refs/heads/main"
      
      - name: Post success comment
        if: success()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '✅ **MCPTrust Verified** — Lockfile signature valid (Sigstore keyless)'
            })
```

## CLI Reference

### Signing

```bash
# Ed25519 (default)
mcptrust sign --key private.key

# Sigstore keyless
mcptrust sign --sigstore

# Custom lockfile path
mcptrust sign --sigstore --lockfile custom-lock.json

# Also save raw bundle
mcptrust sign --sigstore --bundle-out bundle.json
```

### Verification

```bash
# Ed25519 (auto-detected from signature)
mcptrust verify --key public.key

# Sigstore (exact identity match)
mcptrust verify mcp-lock.json \
  --issuer https://token.actions.githubusercontent.com \
  --identity "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main"

# Sigstore (regex pattern)
mcptrust verify mcp-lock.json \
  --issuer https://token.actions.githubusercontent.com \
  --identity-regexp "https://github.com/org/repo/.*"

# GitHub Actions preset (sets issuer automatically)
mcptrust verify mcp-lock.json \
  --github-actions \
  --identity "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main"
```

## Identity Format (GitHub Actions)

GitHub Actions OIDC identity follows this pattern:

```
https://github.com/{owner}/{repo}/.github/workflows/{workflow_file}@refs/heads/{branch}
```

Examples:
- `https://github.com/mcptrust/mcptrust/.github/workflows/sign.yml@refs/heads/main`
- `https://github.com/myorg/myapp/.github/workflows/release.yml@refs/tags/v1.0.0`

## Security Considerations

> [!IMPORTANT]
> Always specify `--issuer` and `--identity` for verification. These parameters prevent supply chain attacks where an attacker signs with their own identity.

> [!TIP]
> **Offline verification**: Cosign bundles support offline verification. If your `.sig` file contains a v3 Sigstore signature, the embedded bundle can be verified without network access:
> ```bash
> # Extract bundle from .sig, then verify offline
> cosign verify-blob --bundle bundle.json \
>   --certificate-identity "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main" \
>   --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
>   --offline mcp-lock.json
> ```

> [!CAUTION]
> **Transparency logs are public and immutable.** When you sign with Sigstore, your identity (email or workflow URI) is permanently recorded in Rekor. This cannot be undone. Consider this before signing with personal email addresses.

**Best practices:**
1. Use exact `--identity` match in production
2. Use `--identity-regexp` only for development/testing
3. Pin cosign version in CI workflows
4. Verify the workflow file path matches your actual signing workflow
5. **Prefer pinning to tags** (e.g., `@refs/tags/v1.0.0`) over mutable refs (e.g., `@refs/heads/main`) for stricter governance

## What to Paste (Copy-Ready Verify Command)

For GitHub Actions-signed lockfiles:

```bash
mcptrust verify mcp-lock.json \
  --issuer https://token.actions.githubusercontent.com \
  --identity "https://github.com/${GITHUB_REPOSITORY}/.github/workflows/sign.yml@refs/heads/main"
```

Replace `${GITHUB_REPOSITORY}` with your actual `owner/repo`.

## How to Find Your Correct Identity

Identity and issuer differ between local keyless signing and GitHub Actions.

### Step 1: Discover the actual identity

Use `--certificate-identity-regexp '.*'` to see what identity was recorded:

```bash
# Extract bundle from signature (if needed)
# The .sig file contains base64-encoded bundle after the header line

# Verify with wildcard to discover identity
cosign verify-blob --bundle bundle.json \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  mcp-lock.json
```

This prints the certificate subject (identity). Use that exact value.

### Step 2: Tighten to exact match

Once you know the identity, switch to exact match:

```bash
mcptrust verify mcp-lock.json \
  --issuer https://token.actions.githubusercontent.com \
  --identity "https://github.com/myorg/myrepo/.github/workflows/sign.yml@refs/heads/main"
```

## Why Issuer Mismatch Happens

The **OIDC issuer** is the identity provider that authenticated you, not Sigstore's auth UI.

| How you logged in | Issuer |
|-------------------|--------|
| GitHub Actions workflow | `https://token.actions.githubusercontent.com` |
| Local browser → Google account | `https://accounts.google.com` |
| Local browser → GitHub login | `https://github.com/login/oauth` |
| Local browser → Microsoft | `https://login.microsoftonline.com/...` |

`oauth2.sigstore.dev` is Sigstore's OAuth frontend—it redirects to your actual IdP. The issuer in the certificate is the IdP, not Sigstore.

**Common mistake:** Expecting GitHub Actions issuer when you signed locally with Google.

## Troubleshooting

### "cosign not found"

Install cosign: https://docs.sigstore.dev/cosign/installation/

```bash
# macOS
brew install cosign

# Linux
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o cosign
chmod +x cosign && sudo mv cosign /usr/local/bin/
```

### "no identity token found"

Keyless signing requires OIDC. In GitHub Actions, ensure:

```yaml
permissions:
  id-token: write
```

### Verification fails with wrong identity

Check the actual identity in the signature:

```bash
# Extract bundle from .sig file, then:
cosign verify-blob --bundle bundle.json \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  mcp-lock.json
```

This shows the actual certificate identity for debugging.

### v3 signature not recognized

Error like "Sigstore signature must have a header with canon_version"?

This means you're using an older MCPTrust version that doesn't support v3 signatures.

**Solution:** Upgrade MCPTrust:

```bash
go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest
```

