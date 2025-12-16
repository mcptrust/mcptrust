# Security Policy

## Supported Versions

Only the latest `main` branch is currently supported.

| Version | Supported          |
| ------- | ------------------ |
| v0.1.x  | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in MCPTrust, please do **not** open a public issue.

**Preferred:** [Open a private security advisory](https://github.com/mcptrust/mcptrust/security/advisories/new)

**Email:** security@mcptrust.dev

We will acknowledge reports within 48 hours.

### Scope

We are particularly interested in:
*   Bypasses of the `verify` command.
*   Hash collisions that allow malicious tool changes to go undetected.
*   Non-determinism in the locking or bundling process.
