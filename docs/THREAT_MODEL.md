# Threat Model

## Attacker Model

We assume an attacker who:
1.  **Can control the package registry**: (e.g., publishing a malicious version of an NPM package).
2.  **Can modify network traffic**: (e.g., Man-in-the-Middle) during the download of tools or bundles.
3.  **Cannot access the private key**: The signing key is assumed to be secure.

## Defense Scope

### In Scope (What we protect against)

*   **Supply Chain Drift**: Preventing an agent from using a server that has silently changed its capabilities (e.g., added a `exec` tool) since it was approved.
    *   *Mechanism*: `mcptrust lock` captures hashes; `mcptrust diff` detects drift.
*   **Tampering**: Detecting if an authorized lockfile has been modified to permit unauthorized tools.
    *   *Mechanism*: Ed25519 signatures.
*   **Bundle Corruption**: Detecting if a distribution bundle (zip) has been modified in transit.
    *   *Mechanism*: Signature verification of contents.

### Out of Scope (What we do NOT protect against)

*   **Malicious Implementation Logic**: We verify the *interface* (schema), not the *implementation*. If a tool described as `read_file` actually executes `rm -rf`, MCPTrust cannot detect this via scanning.
*   **Runtime Prompt Injection**: We do not monitor the conversation between the agent and the tool.
*   **Key Compromise**: If an attacker steals `private.key`, they can sign malicious lockfiles.
