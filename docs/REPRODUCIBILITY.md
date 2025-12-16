# Reproducibility

MCPTrust guarantees that `bundle export` is deterministic.

## What is Deterministic?

If you run `mcptrust bundle export` twice on the exact same input files (`mcp-lock.json`, etc.), you will get bit-for-bit identical `bundle.zip` files.

This is achieved by:
1.  **Fixed Timestamps**: All file entry timestamps in the ZIP are set to `January 1, 2025 00:00:00 UTC`.
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

We do not rely on standard library JSON marshaling for hashes. Instead, we use a custom **Canonical JSON** process:

1.  **Maps/Objects**: All keys are sorted alphabetically before marshaling.
2.  **Order Dependence**: The JSON `{ "a": 1, "b": 2 }` results in the exact same hash as `{ "b": 2, "a": 1 }`.
3.  **Whitespace**: The canonical form uses dense JSON (no whitespace).

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
