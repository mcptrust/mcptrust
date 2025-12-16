# Security Model

This document describes MCPTrust's security guarantees and limitations.

See the main security guarantees documentation: [SECURITY_GUARANTEES.md](../SECURITY_GUARANTEES.md)

## Quick Reference

| What MCPTrust Guarantees | What It Does NOT Guarantee |
|--------------------------|---------------------------|
| Lockfile integrity (Ed25519) | Runtime behavior of tools |
| Drift detection (hash comparison) | Protection against prompt injection |
| Deterministic bundles | Security if private key is compromised |

For the full threat model, see [THREAT_MODEL.md](THREAT_MODEL.md).
