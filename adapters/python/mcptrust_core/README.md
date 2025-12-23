# mcptrust-core

Python wrapper for the [mcptrust](https://github.com/mcptrust/mcptrust) CLI.

## Installation

```bash
# From source
pip install -e .

# From PyPI (when published)
pip install mcptrust-core
```

## Requirements

- Python >= 3.10
- `mcptrust` CLI installed and on PATH (or set `MCPTRUST_BIN` environment variable)

## Quick Start

```python
from mcptrust_core import MCPTrust, MCPTrustNotInstalled, MCPTrustCommandError

# Initialize (auto-discovers mcptrust binary)
try:
    m = MCPTrust()
except MCPTrustNotInstalled:
    print("Install mcptrust: go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest")

# Lock a server's current state
m.lock(server_command="npx -y @modelcontextprotocol/server-filesystem /tmp")
# or safer (preferred when paths have spaces):
m.lock(server_argv=["npx", "-y", "@scope/server", "/path with spaces"])

# Check for drift + policy violations (non-throwing by default)
check = m.check(
    server_command="npx -y @modelcontextprotocol/server-filesystem /tmp",
    lockfile="mcp-lock.json",
    preset="strict"
)
if not check.passed:
    print("Drift or policy violation:", check.diff_stdout, check.policy_stdout)
    exit(1)

# Run with enforced verification (raises on failure by default)
try:
    run = m.run(lockfile="mcp-lock.json", dry_run=True)
    print(f"Exit code: {run.exit_code}")
except MCPTrustCommandError as e:
    print(f"Run failed: {e}")
```

## API Reference

### MCPTrust

```python
class MCPTrust:
    def __init__(self, bin_path: str | None = None):
        """Binary discovery: bin_path → MCPTRUST_BIN → PATH."""

    def lock(
        self,
        server_command: str | None = None,  # convenience, shlex-parsed
        *,
        server_argv: list[str] | None = None,  # preferred
        lockfile: str = "mcp-lock.json",
        pin: bool = True,
        verify_provenance: bool = False,
    ) -> LockResult:
        """Lock a server's current state. Raises on failure."""

    def check(
        self,
        server_command: str | None = None,
        *,
        server_argv: list[str] | None = None,
        lockfile: str = "mcp-lock.json",
        preset: str = "baseline",
        raise_on_fail: bool = False,  # non-throwing by default
    ) -> CheckResult:
        """Run diff + policy check. Non-throwing by default for CI flexibility."""

    def run(
        self,
        *,
        lockfile: str = "mcp-lock.json",
        require_provenance: bool = False,
        dry_run: bool = False,
        raise_on_fail: bool = True,  # raises by default
    ) -> RunResult:
        """Run server from verified artifact. Raises on failure by default."""
```

### Exceptions

```python
MCPTrustError           # Base exception
MCPTrustNotInstalled    # Binary not found
MCPTrustCommandError    # Non-zero exit (has .exit_code, .stdout, .stderr)
```

### Error Handling Philosophy

| Method | Default behavior | Set `raise_on_fail=...` for opposite |
|--------|-----------------|-------------------------------------|
| `lock()` | Raises | (always raises) |
| `check()` | Returns `CheckResult(passed=False)` | `True` to raise |
| `run()` | Raises | `False` to return `RunResult` |

`check()` is non-throwing by default so CI/code can decide what to do with failures.

## Testing

```bash
# Unit tests (no mcptrust binary required)
pytest

# With coverage
pytest --cov=mcptrust_core
```

## License

Apache-2.0
