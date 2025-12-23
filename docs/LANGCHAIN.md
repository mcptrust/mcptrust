# LangChain Integration

MCPTrust provides a Python adapter for LangChain agents.

## Install

```bash
pip install langchain-mcptrust
```

Or from source:

```bash
cd adapters/python/langchain_mcptrust
pip install -e .
```

## Quick Start

```python
from langchain_mcptrust import TrustedMCPServer
from mcptrust import MCPTrust

# Initialize
mcp = MCPTrust()
server = TrustedMCPServer(
    mcp=mcp,
    server_command="npx -y @modelcontextprotocol/server-filesystem /tmp",
    lockfile="mcp-lock.json",
)

# Lock the server (generates mcp-lock.json)
server.lock()

# Check for drift
result = server.check()
if not result.passed:
    raise Exception("Server drift detected!")

# Run with enforcement
server.run()
```

## API

| Method | Purpose |
|--------|---------|
| `lock()` | Generate lockfile from server |
| `check()` | Verify server matches lockfile |
| `run()` | Execute with trust enforcement |

## With LangChain Agent

```python
from langchain_mcptrust import TrustedMCPServer, tools_from_schema
from langchain.agents import create_tool_calling_agent

# Get tools from locked server
mcp = MCPTrust()
server = TrustedMCPServer(mcp=mcp, server_command="...", lockfile="mcp-lock.json")
tools = tools_from_schema(server.schema)

# Use in agent
agent = create_tool_calling_agent(llm, tools, prompt)
```

## See Also

- [Python Adapters README](../adapters/python/README.md)
- [CLI Reference](CLI.md)
