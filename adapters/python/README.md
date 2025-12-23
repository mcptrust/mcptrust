# MCPTrust Python Adapters

Official Python wrappers for [MCPTrust](https://github.com/mcptrust/mcptrust).

## Packages

| Package | Description |
|---------|-------------|
| [mcptrust-core](./mcptrust_core/) | Safe subprocess wrapper around the `mcptrust` CLI |
| [langchain-mcptrust](./langchain_mcptrust/) | LangChain integration for trust enforcement |
| [autogen-mcptrust](./autogen_mcptrust/) | AutoGen integration for trust enforcement |
| [crewai-mcptrust](./crewai_mcptrust/) | CrewAI integration for trust enforcement |

## Installation (From Source)

```bash
# Core package
pip install -e ./mcptrust_core

# LangChain adapter (includes mcptrust-core)
pip install -e ./langchain_mcptrust

# AutoGen adapter (includes mcptrust-core)
pip install -e ./autogen_mcptrust

# CrewAI adapter (includes mcptrust-core)
pip install -e ./crewai_mcptrust
```

## Requirements

- Python >= 3.10
- `mcptrust` CLI installed and on PATH (or set `MCPTRUST_BIN`)

## Quick Start

```python
from mcptrust_core import MCPTrust

# Initialize (auto-discovers mcptrust binary)
m = MCPTrust()

# Lock a server's current state
m.lock("npx -y @modelcontextprotocol/server-filesystem /tmp")

# Check for drift against lockfile
result = m.check("npx -y @modelcontextprotocol/server-filesystem /tmp")
print(f"Passed: {result.passed}")
```

## Roadmap

- [x] mcptrust-core
- [x] langchain-mcptrust
- [x] autogen-mcptrust
- [x] crewai-mcptrust
