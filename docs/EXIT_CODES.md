# Exit Codes

MCPTrust uses strict exit codes to allow reliable scripting and CI/CD integration.

| Code | Meaning | Description |
| :--- | :--- | :--- |
| `1` | **Failure** | - Drift detected<br>- Signature invalid / Tampering detected<br>- Policy violation<br>- General application error |
| `2` | **Usage Error** | - Missing arguments (e.g., `diff` without server command) |

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
