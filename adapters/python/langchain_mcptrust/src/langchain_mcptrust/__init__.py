"""langchain-mcptrust: LangChain integration for MCPTrust trust enforcement."""

from .server import TrustedMCPServer, MCPTrustServer  # MCPTrustServer is alias
from .tools import tools_from_schema

__version__ = "0.1.0"

__all__ = [
    "TrustedMCPServer",
    "MCPTrustServer",  # backward compat alias
    "tools_from_schema",
]
