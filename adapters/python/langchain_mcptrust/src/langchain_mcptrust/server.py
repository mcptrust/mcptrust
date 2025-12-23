"""TrustedMCPServer - Trust enforcement wrapper for MCP servers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcptrust_core import MCPTrust
    from mcptrust_core.types import LockResult, CheckResult, RunResult, LogConfig, ReceiptConfig


class TrustedMCPServer:
    """MCPTrust wrapper for LangChain.
    
    Manages trust enforcement (locking/checking). NOT a transport client.
    """
    
    def __init__(
        self,
        mcp: MCPTrust,
        server_command: str | None = None,
        *,
        server_argv: list[str] | None = None,
        lockfile: str = "mcp-lock.json",
        preset: str = "baseline",
    ):
        """Initialize wrapper."""
        self._mcp = mcp
        self._server_command = server_command
        self._server_argv = server_argv
        self._lockfile = lockfile
        self._preset = preset
    
    @property
    def mcp(self) -> MCPTrust:
        """Return the underlying MCPTrust instance."""
        return self._mcp
    
    @property
    def server_command(self) -> str | None:
        """Return the configured server command string."""
        return self._server_command
    
    @property
    def server_argv(self) -> list[str] | None:
        """Return the configured server argv."""
        return self._server_argv
    
    @property
    def lockfile(self) -> str:
        """Return the lockfile path."""
        return self._lockfile
    
    @property
    def preset(self) -> str:
        """Return the policy preset."""
        return self._preset
    
    def lock(
        self,
        *,
        pin: bool = True,
        verify_provenance: bool = False,
        timeout: int | None = None,
        log: LogConfig | None = None,
        receipt: ReceiptConfig | None = None,
    ) -> LockResult:
        """Lock server state."""
        return self._mcp.lock(
            self._server_command,
            server_argv=self._server_argv,
            lockfile=self._lockfile,
            pin=pin,
            verify_provenance=verify_provenance,
            timeout=timeout,
            log=log,
            receipt=receipt,
        )
    
    def check(
        self,
        *,
        timeout: int | None = None,
        log: LogConfig | None = None,
        receipt: ReceiptConfig | None = None,
        raise_on_fail: bool = False,
    ) -> CheckResult:
        """Check for drift/policy violations."""
        return self._mcp.check(
            self._server_command,
            server_argv=self._server_argv,
            lockfile=self._lockfile,
            preset=self._preset,
            timeout=timeout,
            log=log,
            receipt=receipt,
            raise_on_fail=raise_on_fail,
        )
    
    def run(
        self,
        *,
        require_provenance: bool = False,
        dry_run: bool = False,
        bin_name: str | None = None,
        timeout: int | None = None,
        log: LogConfig | None = None,
        receipt: ReceiptConfig | None = None,
        raise_on_fail: bool = True,
    ) -> RunResult:
        """Run verified server."""
        return self._mcp.run(
            lockfile=self._lockfile,
            require_provenance=require_provenance,
            dry_run=dry_run,
            bin_name=bin_name,
            timeout=timeout,
            log=log,
            receipt=receipt,
            raise_on_fail=raise_on_fail,
        )


# Backward compatibility alias
MCPTrustServer = TrustedMCPServer
