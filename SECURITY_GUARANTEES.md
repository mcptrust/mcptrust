# MCPTrust Security Guarantees

This document outlines the specific security properties guaranteed by the MCPTrust toolchain when used correctly.

## 1. Integrity (The Lockfile)
**Guarantee**: If `mcptrust verify` passes, the `mcp-lock.json` file bytes have not been modified by a single bit since it was signed.

*   **Mechanism**: Ed25519 digital signatures.
*   **Proof**: The `tests/gauntlet.sh` suite includes a "Tamper Detection" phase that flips a single bit in the lockfile and asserts verification failure.

## 2. Authenticity (The Signature)
**Guarantee**: If `mcptrust verify` passes, the `mcp-lock.json` was definitely signed by the holder of the private key corresponding to the provided `public.key`.

*   **Mechanism**: Ed25519 public-key cryptography.
*   **Proof**: The `tests/gauntlet.sh` suite attempts verification with a different (but valid) public key and asserts failure.

## 3. Drift Detection (The Diff)
**Guarantee**: `mcptrust diff` will accurately report *any* semantic change in the MCP server's tools compared to the lockfile.

*   **Mechanism**: Structural JSON hashing of tool descriptions and input schemas.
*   **Properties**:
    *   **Schema Changes**: Modifying a parameter from `string` to `number` triggers an alert.
    *   **Description Changes**: Changing the documentation string triggers an alert.
    *   **Risk Level Changes**: Changing the risk classification triggers a Critical alert.

## 4. Reproducibility (The Bundle)
**Guarantee**: `mcptrust bundle export` is deterministic. Running it multiple times on the same input files will produce a bit-for-bit identical `bundle.zip` hash.

*   **Mechanism**: Canonical zip creation with fixed timestamps (Jan 1, 2025) and deterministic file ordering.
*   **Why It Matters**: Allows auditors to verify that a distributed bundle corresponds exactly to the source artifacts without trusting the transporter.

## 5. Governance (The Policy)
**Guarantee**: `mcptrust policy check` ensures no tools violate the defined CEL rules.

*   **Mechanism**: Google CEL (Common Expression Language) evaluation.
*   **Default Behavior**: Fail-closed. If the policy cannot be evaluated or the server is unreachable, the check fails.
