"""Hook helpers for integrating MCPTrust with CrewAI workflows."""

from __future__ import annotations

from typing import Any, Callable, TYPE_CHECKING

from mcptrust_core.types import CheckResult

from .guard import MCPTrustGuard

if TYPE_CHECKING:
    pass


def ensure_trusted_mcp_server(**kwargs: Any) -> CheckResult:
    """Construct guard, ensure trust."""
    guard = MCPTrustGuard(**kwargs)
    return guard.ensure()


def before_kickoff_callback(
    guard: MCPTrustGuard,
    **ensure_kwargs: Any,
) -> Callable[..., None]:
    """Create pre-kickoff trust hook."""
    def callback(*args: Any, **kwargs: Any) -> None:
        guard.ensure(**ensure_kwargs)
    
    return callback


def wrap_kickoff(
    kickoff_fn: Callable[..., Any],
    guard: MCPTrustGuard,
    **ensure_kwargs: Any,
) -> Callable[..., Any]:
    """Wrap kickoff with trust check."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        guard.ensure(**ensure_kwargs)
        return kickoff_fn(*args, **kwargs)
    
    return wrapper
