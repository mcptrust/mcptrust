# The Gauntlet

"The Gauntlet" is MCPTrust's comprehensive integration test suite. It runs the entire toolchain against a deterministic mock server (or a live optional server) to verify security guarantees.

## Usage

```bash
# Run the full suite
bash tests/gauntlet.sh

# Run in Fixture Mode (no live server dependencies needed)
MCPTRUST_FORCE_FIXTURE=1 bash tests/gauntlet.sh
```

## Prerequisites

*   **Go** (to build the binary)
*   **Bash** (to run the script)
*   **jq** or **python3** (for JSON assertions)
*   **zip** / **unzip** (for bundle verification)

## What It Proves

The Gauntlet moves through multiple phases to prove:

1.  **Discovery**: `mcptrust scan` produces valid JSON reports.
2.  **Governance**: `mcptrust policy check -- <command>` detects violations (if any).
3.  **Persistence**: `mcptrust lock` creates a hash-locked file.
4.  **Identity**: `mcptrust sign/verify` works with Ed25519 keys.
5.  **Distribution**: `mcptrust bundle export` creates valid ZIPs.
6.  **Determinism**: Running the bundle export twice produces bit-for-bit identical ZIPs.
7.  **Tamper Detection**:
    *   It manually flips a bit in `mcp-lock.json` hash.
    *   It asserts that `verify` FAILS (exit 1).
    *   It asserts that `diff` DETECTS the drift (exit 1).
8.  **Negative Tests**: Verified failure on wrong keys and corrupted signatures.
