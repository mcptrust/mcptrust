# Reproducibility

MCPTrust guarantees that `bundle export` is deterministic.

## What is Deterministic?

If you run `mcptrust bundle export` twice on the exact same input files (`mcp-lock.json`, etc.), you will get bit-for-bit identical `bundle.zip` files.

> **Note**: Determinism is guaranteed for the same mcptrust version and Go toolchain. DEFLATE compression output may vary across different Go versions or platforms.

This is achieved by:
1.  **Fixed Timestamps**: All file entry timestamps in the ZIP are set to `January 1, 1980 00:00:00 UTC` (ZIP epoch).
2.  **Sorted Files**: Files are added to the archive in alphabetical order.
3.  **Canonical JSON**: The lockfile itself relies on sorted keys.

## Hashing & Canonicalization

To ensure consistent verification across different machines and OSs, MCPTrust uses strict rules for hashing.

### What is Hashed?

For each tool, we compute two distinct hashes:

1.  **Description Hash**: `SHA-256(tool.Description)`
    *   **Input**: The raw string description provided by the MCP server.
    *   **Normalization**: None. Exact string match required.

2.  **Input Schema Hash**: `SHA-256(CanonicalJSON(tool.InputSchema))`
    *   **Input**: The JSON Schema object defining the tool's arguments.
    *   **Normalization**: Keys are recursively sorted alphabetically.

**Note**: The tool `name` and `risk_level` are **NOT** included in these hashes. Instead, they are tracked structurally in the lockfile:
*   Name changes = Tool Added / Tool Removed events.
*   Risk level changes = Explicit drift event.

### Canonical JSON

We use two canonicalization versions:

**v1 (mcptrust-canon-v1)** — Default, internal format:
1.  Keys sorted alphabetically (Go string/UTF-8 order)
2.  Compact JSON (no whitespace)
3.  Standard JSON string escaping
4.  Numbers preserved as-is from source

**v2 (mcptrust-canon-v2, JCS-like)** — UTF-16 sorted format:
1.  Keys sorted by UTF-16 code unit order (per RFC 8785)
2.  Compact JSON
3.  Go-native number formatting (may differ from ES6 edge cases)
4.  Recommended for new integrations requiring deterministic ordering

> **Note**: v2 follows JCS key ordering but uses Go's number formatting. For strict RFC 8785 interop, verify with external JCS implementations.

### Description Hash Behavior

`description_hash` uses the **exact raw bytes** of the tool description. Whitespace changes (spaces, newlines) WILL trigger drift detection. This is intentional — documentation changes are security-relevant.

> **Note**: v1 is stable and v2 is interoperable. Both produce deterministic output.

### Non-Goals

We explicitly **DO NOT** guarantee stability for:
*   Internal server implementation details (function bodies, etc.).
*   Field order in the raw `mcp-lock.json` file (though we pretty-print it for readability, the *signature* is verified against the canonical form).

## How to Verify

You can verify this property yourself:

1.  **Generate a bundle:**
    ```bash
    mcptrust bundle export -o bundle1.zip
    ```

2.  **Wait** (to ensure system clock changes):
    ```bash
    sleep 2
    ```

3.  **Generate another bundle:**
    ```bash
    mcptrust bundle export -o bundle2.zip
    ```

4.  **Compare Hashes:**
    ```bash
    shasum -a 256 bundle1.zip bundle2.zip
    # Hashes MUST match
    ```

*This process is automated in `tests/gauntlet.sh` Phase 5b.*
