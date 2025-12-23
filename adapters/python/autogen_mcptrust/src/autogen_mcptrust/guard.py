"""MCPTrustGuard: Core trust enforcement wrapper for AutoGen workflows."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from mcptrust_core import MCPTrust
from mcptrust_core.types import LockResult, CheckResult, LogConfig, ReceiptConfig

if TYPE_CHECKING:
    pass


class MCPTrustGuard:
    """Trust enforcement guard for AutoGen.
    
    Wraps MCPTrust to verify server integrity. Does NOT implement transport
    or execution—just ensures state hasn't drifted.
    """
    
    def __init__(
        self,
        *,
        mcp: MCPTrust | None = None,
        server_command: str | None = None,
        server_argv: list[str] | None = None,
        lockfile: str = "mcp-lock.json",
        preset: str = "baseline",
        log: LogConfig | None = None,
        receipt: ReceiptConfig | None = None,
    ):
        """Initialize guard."""
        if not server_command and not server_argv:
            raise ValueError("Must specify server_command or server_argv")
        
        self.mcp = mcp if mcp is not None else MCPTrust()
        # Prefer server_argv when both are provided
        if server_argv:
            self.server_command = None
            self.server_argv = server_argv
        else:
            self.server_command = server_command
            self.server_argv = None
        self.lockfile = lockfile
        self.preset = preset
        self.log = log
        self.receipt = receipt
    
    def lock(
        self,
        *,
        pin: bool = True,
        verify_provenance: bool = False,
    ) -> LockResult:
        """Lock server state. Creates/updates lockfile."""
        return self.mcp.lock(
            self.server_command,
            server_argv=self.server_argv,
            lockfile=self.lockfile,
            pin=pin,
            verify_provenance=verify_provenance,
            log=self.log,
            receipt=self.receipt,
        )
    
    def check(
        self,
        *,
        raise_on_fail: bool = False,
    ) -> CheckResult:
        """Check for drift (diff + policy)."""
        return self.mcp.check(
            self.server_command,
            server_argv=self.server_argv,
            lockfile=self.lockfile,
            preset=self.preset,
            log=self.log,
            receipt=self.receipt,
            raise_on_fail=raise_on_fail,
        )
    
    def ensure(
        self,
        *,
        pin: bool = True,
        verify_provenance: bool = False,
        raise_on_fail: bool = True,
        lock_if_missing: bool = True,
    ) -> CheckResult:
        """Ensure trusted state. Locks if missing, checks if present."""
        if lock_if_missing and not os.path.exists(self.lockfile):
            self.lock(pin=pin, verify_provenance=verify_provenance)
        
        return self.check(raise_on_fail=raise_on_fail)
