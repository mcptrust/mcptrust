# langchain-mcptrust

LangChain integration for [MCPTrust](https://github.com/mcptrust/mcptrust) trust enforcement.

## What This Package Does

This adapter provides a convenience wrapper for enforcing trust policies on MCP servers before using them with LangChain. It:

- **Locks** server capabilities to a lockfile
- **Checks** for drift and policy violations before execution
- **Runs** servers from verified artifacts

## What This Package Does NOT Do

> [!IMPORTANT]
> This adapter **does not** implement MCP transport or tool execution.
> It manages **trust enforcement only**.
> You still need an MCP client library to actually call tools on the server.

## Installation

```bash
# From source
pip install -e .

# From PyPI (when published)
pip install langchain-mcptrust
```

## Requirements

- Python >= 3.10
- `mcptrust` CLI installed and on PATH
- mcptrust-core package (installed automatically)

## Quick Start

```python
from mcptrust_core import MCPTrust
from langchain_mcptrust import TrustedMCPServer

# Initialize
mcp = MCPTrust()
server = TrustedMCPServer(
    mcp=mcp,
    server_command="npx -y @modelcontextprotocol/server-filesystem /tmp",
    # Or use server_argv for robustness:
    # server_argv=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    lockfile="mcp-lock.json",
    preset="baseline",
)

# Lock the server's current state (first time setup)
lock_result = server.lock()

# Before each agent run, check for drift and policy violations
check_result = server.check()
if not check_result.passed:
    raise RuntimeError("Server failed trust check!")

# (Optional) Run with enforced verification
run_result = server.run(dry_run=True)
```

## API Reference

### TrustedMCPServer

```python
class TrustedMCPServer:
    def __init__(
        self,
        mcp: MCPTrust,
        server_command: str | None = None,
        *,
        server_argv: list[str] | None = None,
        lockfile: str = "mcp-lock.json",
        preset: str = "baseline",
    ):
        """
        Initialize a trust-enforced MCP server wrapper.

        Args:
            mcp: MCPTrust instance for CLI operations.
            server_command: Server command as string (convenience, shlex-parsed).
            server_argv: Server command as argv list (preferred for robustness).
            lockfile: Path to the lockfile.
            preset: Policy preset ("baseline" or "strict").
        """

    def lock(self, **kwargs) -> LockResult:
        """Lock the server's current state."""

    def check(self, **kwargs) -> CheckResult:
        """Check for drift and policy violations."""

    def run(self, *, check=True, **kwargs) -> RunResult:
        """Run server from verified artifact. Raises on failure by default."""
```

### tools_from_schema

```python
def tools_from_schema(schema: dict) -> list:
    """
    Best-effort tool schema to Python mapping.
    
    Returns empty list if schema format is not recognized.
    This is a stub for future LangChain tool integration.
    """
```

## Workflow Example

```python
from mcptrust_core import MCPTrust
from langchain_mcptrust import TrustedMCPServer

# Setup (once)
mcp = MCPTrust()
server = TrustedMCPServer(
    mcp=mcp,
    server_argv=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    preset="strict",
)

# CI/CD: Lock and commit lockfile
server.lock(verify_provenance=True)

# Runtime: Verify before use
result = server.check()
if not result.passed:
    # Handle drift or policy violations
    print("Diff output:", result.diff_stdout)
    print("Policy output:", result.policy_stdout)
    exit(1)

# Safe to proceed with MCP client...
```

## Limitations

- Does **not** implement MCP transport protocol
- Does **not** execute MCP tools directly
- Requires `mcptrust` CLI to be installed
- Tool schema mapping is best-effort placeholder

## License

Apache-2.0
