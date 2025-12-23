"""mcptrust-core: Python wrapper for the mcptrust CLI."""

from .cli import MCPTrust
from .errors import MCPTrustError, MCPTrustNotInstalled, MCPTrustCommandError
from .types import LockResult, CheckResult, RunResult, ReceiptConfig, LogConfig

__version__ = "0.1.0"

__all__ = [
    "MCPTrust",
    "MCPTrustError",
    "MCPTrustNotInstalled",
    "MCPTrustCommandError",
    "LockResult",
    "CheckResult",
    "RunResult",
    "ReceiptConfig",
    "LogConfig",
]
