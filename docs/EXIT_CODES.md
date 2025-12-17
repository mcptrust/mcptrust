# Exit Codes

MCPTrust uses strict exit codes for CI/CD integration.

| Code | Category | Examples |
| :--- | :--- | :--- |
| `0` | **Success** | Verification passed, no drift, policy passed |
| `1` | **Failure** | Drift detected, signature invalid, policy violation |
| `2` | **Operational Error** | Missing args, IO error, parse error, cosign missing |

## Command Behavior

### `mcptrust verify`
*   **0**: Signature is valid.
*   **1**: Tampering detected OR wrong key used. (Verified by Gauntlet Phase 6, 7, 8)

### `mcptrust diff`
*   **0**: No changes detected.
*   **1**: Drift detected (e.g., description changed). (Verified by Gauntlet Phase 6)
*   **2**: Usage error (e.g., missing `-- <command>`).

### `mcptrust policy check`
*   **0**: All rules passed.
*   **1**: At least one rule failed. (Verified by Gauntlet Phase 10)
