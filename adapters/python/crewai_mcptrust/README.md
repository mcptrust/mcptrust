# crewai-mcptrust

Trust enforcement for [CrewAI](https://www.crewai.com/) workflows using [MCPTrust](https://github.com/mcptrust/mcptrust).

## What This Does

Runs MCPTrust `lock` and `check` commands to detect drift and enforce policy **before** you use an MCP server in a CrewAI workflow.

## What This Does NOT Do

- **Does not implement MCP transport/client** — you still need your own MCP client implementation
- **Does not automatically register tools into CrewAI** — tool registration is your responsibility
- **Does not execute or proxy MCP tool calls** — it only verifies the server hasn't changed
- **Does not integrate with CrewAI internals** — works with any kickoff/run function

This adapter is intentionally thin. It ensures your MCP server matches its locked state before you start a workflow.

## Installation

```bash
pip install crewai-mcptrust
```

Requires `mcptrust` CLI on PATH. Install with:
```bash
go install github.com/mcptrust/mcptrust/cmd/mcptrust@v0.1.1
```

## Quick Start

### Using `server_argv` (Preferred)

```python
from crewai_mcptrust import MCPTrustGuard

guard = MCPTrustGuard(
    server_argv=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    preset="strict",
)

# Ensure trust: lock if missing, then check for drift
guard.ensure(pin=True)

# Safe to proceed with Crew.kickoff()...
```

### Using `server_command` (String)

```python
from crewai_mcptrust import MCPTrustGuard

guard = MCPTrustGuard(
    server_command="npx -y @modelcontextprotocol/server-filesystem /tmp",
)

guard.ensure()

# Crew.kickoff() as usual...
```

> [!TIP]
> **Prefer `server_argv`** over `server_command` when your command contains special characters.
> If both are provided, `server_argv` takes precedence.

## Kickoff Wrapper

Wrap your `Crew.kickoff` method to automatically ensure trust:

```python
from crewai_mcptrust import MCPTrustGuard, wrap_kickoff
from crewai import Crew

crew = Crew(agents=[...], tasks=[...])
guard = MCPTrustGuard(
    server_argv=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
)

secure_kickoff = wrap_kickoff(crew.kickoff, guard, pin=True)
result = secure_kickoff()  # Verifies trust, then runs kickoff
```

## Pre-execution Callback (Generic)

Use a helper to generate a callback for pre-execution hooks:

```python
from crewai_mcptrust import MCPTrustGuard, before_kickoff_callback

guard = MCPTrustGuard(server_argv=["npx", "-y", "server"])
hook = before_kickoff_callback(guard, pin=True)

hook()  # Call this before Crew.kickoff()
crew.kickoff()
```

## One-Shot Helper

For simple use cases:

```python
from crewai_mcptrust import ensure_trusted_mcp_server

ensure_trusted_mcp_server(
    server_argv=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    preset="strict",
)
```

## Logging and Receipts

Pass `LogConfig` and `ReceiptConfig` for observability:

```python
from crewai_mcptrust import MCPTrustGuard
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

### Generic Helpers

- `ensure_trusted_mcp_server(**kwargs) -> CheckResult` — One-shot guard + ensure
- `before_kickoff_callback(guard, **ensure_kwargs) -> Callable` — Returns callable compatible with CrewAI callbacks
- `wrap_kickoff(kickoff_fn, guard, **ensure_kwargs) -> Callable` — Wraps function with trust check

## CI Best Practices

1. **Pin versions**: Lock `mcptrust-core` version in your requirements
   ```
   mcptrust-core==0.1.0
   crewai-mcptrust==0.1.0
   ```

2. **Use strict preset**: In production, use `preset="strict"` to fail on any drift

3. **Save receipts**: Configure `ReceiptConfig` and upload as CI artifacts
   ```yaml
   - name: Upload MCPTrust Receipt
     uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.0
     with:
       name: mcptrust-receipt
       path: receipts/mcptrust-receipt.json
   ```

4. **Prefer `server_argv`**: Avoids shell parsing issues with special characters

## License

Apache-2.0
