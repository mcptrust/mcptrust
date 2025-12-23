# autogen-mcptrust

Trust enforcement for [AutoGen](https://microsoft.github.io/autogen/) workflows using [MCPTrust](https://github.com/mcptrust/mcptrust).

## What This Does

Runs MCPTrust `lock` and `check` commands to detect drift and enforce policy **before** you use an MCP server in an AutoGen workflow.

## What This Does NOT Do

- **Does not implement MCP transport/client** — you still need your own MCP client implementation
- **Does not automatically register tools into AutoGen** — tool registration is your responsibility
- **Does not execute or proxy MCP tool calls** — it only verifies the server hasn't changed

This adapter is intentionally thin. It ensures your MCP server matches its locked state before you start a workflow.

## Installation

```bash
pip install autogen-mcptrust
```

Requires `mcptrust` CLI on PATH. Install with:
```bash
go install github.com/mcptrust/mcptrust/cmd/mcptrust@v0.1.1
```

## Quick Start

```python
from autogen_mcptrust import MCPTrustGuard

guard = MCPTrustGuard(
    server_command="npx -y @modelcontextprotocol/server-filesystem /tmp",
    # Or use server_argv for robustness:
    # server_argv=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    preset="strict",
)

# Ensure trust: lock if missing, then check for drift
guard.ensure(pin=True)

# Safe to proceed with your AutoGen workflow...
```

> [!TIP]
> **Prefer `server_argv`** over `server_command` when your command contains special characters.
> If both are provided, `server_argv` takes precedence.

## Hook Helpers

### Pre-execution Callback

```python
from autogen_mcptrust import MCPTrustGuard, before_chat_callback

guard = MCPTrustGuard(server_argv=["npx", "-y", "server"])
hook = before_chat_callback(guard, pin=True)

# Call before starting the workflow
hook()
```

### Wrap a Runner Function

```python
from autogen_mcptrust import MCPTrustGuard, wrap_runner

def start_workflow():
    # ... your AutoGen workflow code ...
    pass

guard = MCPTrustGuard(server_argv=["npx", "-y", "server"])
safe_start = wrap_runner(start_workflow, guard)
safe_start()  # Verifies trust, then runs
```

### One-Shot Helper

```python
from autogen_mcptrust import ensure_trusted_mcp_server

ensure_trusted_mcp_server(
    server_argv=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    preset="strict",
)
```

## Logging and Receipts

Pass `LogConfig` and `ReceiptConfig` for observability:

```python
from autogen_mcptrust import MCPTrustGuard
from mcptrust_core.types import LogConfig, ReceiptConfig

guard = MCPTrustGuard(
    server_argv=["npx", "-y", "server"],
    log=LogConfig(format="jsonl", level="info", output="mcptrust.log"),
    receipt=ReceiptConfig(path="receipts/mcptrust-receipt.json"),
)
guard.ensure()
```

## API Reference

### `MCPTrustGuard`

```python
MCPTrustGuard(
    *,
    mcp: MCPTrust | None = None,
    server_command: str | None = None,
    server_argv: list[str] | None = None,
    lockfile: str = "mcp-lock.json",
    preset: str = "baseline",
    log: LogConfig | None = None,
    receipt: ReceiptConfig | None = None,
)
```

Methods:
- `lock(*, pin=True, verify_provenance=False) -> LockResult`
- `check(*, raise_on_fail=False) -> CheckResult`
- `ensure(*, pin=True, verify_provenance=False, raise_on_fail=True, lock_if_missing=True) -> CheckResult`

### Hook Functions

- `ensure_trusted_mcp_server(**kwargs) -> CheckResult` — One-shot guard + ensure
- `before_chat_callback(guard, **ensure_kwargs) -> Callable` — Returns pre-execution hook
- `wrap_runner(fn, guard, **ensure_kwargs) -> Callable` — Wraps function with trust check

## Best Practices

1. **Pin versions**: Lock `mcptrust-core` version in your requirements
2. **Use strict preset**: In production, use `preset="strict"` to fail on any drift
3. **Save receipts**: Configure `ReceiptConfig` and archive receipts in CI artifacts
4. **Prefer `server_argv`**: Avoids shell parsing issues with special characters

## License

Apache-2.0
