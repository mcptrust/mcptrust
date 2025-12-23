# Maintainer Verification Checklist

Quick checklist for verifying MCPTrust before release.

## Build & Test

```bash
# Must pass
go build ./...
go test ./... -v

# Integration tests (uses mock server)
bash tests/gauntlet.sh

# Fixture mode (CI behavior)
MCPTRUST_FORCE_FIXTURE=1 bash tests/gauntlet.sh
```

## Manual Smoke Test

```bash
# Build binary
go build -o mcptrust ./cmd/mcptrust

# Basic lock (always works)
./mcptrust lock -- "./tests/fixtures/mock_mcp_server/mock_mcp_server"

# Sign and verify roundtrip
./mcptrust keygen
./mcptrust sign --key private.key mcp-lock.json
./mcptrust verify --key public.key mcp-lock.json
# Expected: exit 0, "Signature valid"
```

## Supply Chain Tests (Optional, requires network)

```bash
# Requires npx
./mcptrust lock --pin -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
cat mcp-lock.json | jq '.artifact'
# Expected: artifact object with name, version, integrity

# Requires cosign (brew install cosign)
./mcptrust lock --pin --verify-provenance -- "npx -y @modelcontextprotocol/server-filesystem /tmp"
# Note: May fail if package lacks SLSA provenance

# Artifact verify
./mcptrust artifact verify mcp-lock.json
# Expected: exit 0 if integrity matches
```

## Policy Preset Tests

```bash
# Baseline (exit 0 with warnings)
./mcptrust policy check --preset baseline -- "./tests/fixtures/mock_mcp_server/mock_mcp_server"
echo "Exit code: $?"
# Expected: exit 0

# Strict (exit 1 without lockfile artifact)
./mcptrust policy check --preset strict -- "./tests/fixtures/mock_mcp_server/mock_mcp_server"
echo "Exit code: $?"
# Expected: exit 1 (no artifact pinned)

# Strict with lockfile
./mcptrust policy check --preset strict --lockfile mcp-lock.json -- "./tests/fixtures/mock_mcp_server/mock_mcp_server"
# Expected: depends on lockfile content
```

## Tool Installation

```bash
# macOS
brew install cosign

# Linux
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# Verify npm version (for fallback)
npm --version  # Should be >= 9.5
```

## Expected Gauntlet Output

```
Total Tests:  33+
Passed:       33+
Failed:       0

ALL TESTS PASSED! 🎉
```
