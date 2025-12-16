# Changelog

All notable changes to this project will be documented in this file.

## v0.1.0 (2025-12-15)

Initial release of MCPTrust.

### Features

*   **Scan**: Interrogates MCP servers via stdio transport to discover capabilities.
*   **Lock**: Generates `mcp-lock.json` with SHA-256 hashes of tool schemas and descriptions.
*   **Sign/Verify**: Implements Ed25519 signing for lockfile integrity.
*   **Diff**: Semantic drift detection showing exactly what changed between a lockfile and a live server.
*   **Bundle**: Exports deterministic ZIP bundles with embedded `manifest.json` (includes tool version, file hashes, and canonicalization version).
*   **Policy**: Enforce security rules using Common Expression Language (CEL).

### Security

*   **Canonicalization versioning**: v1 (default) for existing behavior, v2 (opt-in) for JCS RFC 8785 compliance. Use `--canonicalization v2` when needed.
*   **Deterministic bundling**: Fixed timestamps (2025-01-01 UTC), alphabetical file ordering, consistent compression.
*   **Backward compatibility**: Legacy signatures (raw hex, no header) are auto-detected and verified as v1.
*   "Gauntlet" integration test suite verifies tamper detection and bundle reproducibility.
