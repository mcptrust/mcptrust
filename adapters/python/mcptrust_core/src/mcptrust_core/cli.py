"""Main MCPTrust CLI wrapper."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from typing import TYPE_CHECKING

from .errors import MCPTrustNotInstalled, MCPTrustCommandError
from .types import LockResult, CheckResult, RunResult, LogConfig, ReceiptConfig

if TYPE_CHECKING:
    from subprocess import CompletedProcess


class MCPTrust:
    """Python wrapper for mcptrust CLI."""
    
    def __init__(self, bin_path: str | None = None):
        """Initialize wrapper. Locates binary via arg, env, or PATH."""
        if bin_path:
            self._bin_path = bin_path
        elif env_bin := os.environ.get("MCPTRUST_BIN"):
            self._bin_path = env_bin
        elif which_bin := shutil.which("mcptrust"):
            self._bin_path = which_bin
        else:
            raise MCPTrustNotInstalled()
    
    @property
    def bin_path(self) -> str:
        """Return the resolved path to the mcptrust binary."""
        return self._bin_path
    
    def _run(
        self,
        argv: list[str],
        *,
        timeout: int | None = None,
    ) -> CompletedProcess[str]:
        """Execute mcptrust locally."""
        full_argv = [self._bin_path] + argv
        
        result = subprocess.run(
            full_argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        if result.returncode != 0:
            raise MCPTrustCommandError(
                f"mcptrust exited with code {result.returncode}",
                exit_code=result.returncode,
                argv=full_argv,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        
        return result
    
    def _build_common_flags(
        self,
        log: LogConfig | None = None,
        receipt: ReceiptConfig | None = None,
    ) -> list[str]:
        """Build common CLI flags for logging and receipts."""
        flags: list[str] = []
        
        if log:
            flags.extend(["--log-format", log.format])
            flags.extend(["--log-level", log.level])
            flags.extend(["--log-output", log.output])
        
        if receipt:
            flags.extend(["--receipt", receipt.path])
            flags.extend(["--receipt-mode", receipt.mode])
        
        return flags
    
    def _parse_server_command(
        self,
        server_command: str | None,
        server_argv: list[str] | None,
    ) -> list[str]:
        """Parse command to argv."""
        if server_command and server_argv:
            raise ValueError("Specify server_command OR server_argv, not both")
        if server_argv:
            return list(server_argv)
        if server_command:
            return shlex.split(server_command)
        raise ValueError("Must specify server_command or server_argv")
    
    def lock(
        self,
        server_command: str | None = None,
        *,
        server_argv: list[str] | None = None,
        lockfile: str = "mcp-lock.json",
        pin: bool = True,
        verify_provenance: bool = False,
        timeout: int | None = None,
        log: LogConfig | None = None,
        receipt: ReceiptConfig | None = None,
    ) -> LockResult:
        """Lock server state."""
        cmd_tokens = self._parse_server_command(server_command, server_argv)
        
        argv = ["lock"]
        argv.extend(self._build_common_flags(log, receipt))
        argv.extend(["--output", lockfile])
        
        if pin:
            argv.append("--pin")
        if verify_provenance:
            argv.append("--verify-provenance")
        
        # Server command tokens go after --
        argv.append("--")
        argv.extend(cmd_tokens)
        
        result = self._run(argv, timeout=timeout)
        
        return LockResult(
            lockfile_path=lockfile,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    
    def check(
        self,
        server_command: str | None = None,
        *,
        server_argv: list[str] | None = None,
        lockfile: str = "mcp-lock.json",
        preset: str = "baseline",
        timeout: int | None = None,
        log: LogConfig | None = None,
        receipt: ReceiptConfig | None = None,
        raise_on_fail: bool = False,
    ) -> CheckResult:
        """Diff + Policy check."""
        cmd_tokens = self._parse_server_command(server_command, server_argv)
        common_flags = self._build_common_flags(log, receipt)
        
        # Run diff
        diff_argv = ["diff", "--lockfile", lockfile]
        diff_argv.extend(common_flags)
        diff_argv.append("--")
        diff_argv.extend(cmd_tokens)
        
        diff_passed = True
        diff_stdout = ""
        diff_stderr = ""
        diff_error: MCPTrustCommandError | None = None
        
        try:
            diff_result = self._run(diff_argv, timeout=timeout)
            diff_stdout = diff_result.stdout
            diff_stderr = diff_result.stderr
        except MCPTrustCommandError as e:
            diff_passed = False
            diff_stdout = e.stdout
            diff_stderr = e.stderr
            diff_error = e
        
        # Run policy check
        policy_argv = ["policy", "check", "--preset", preset, "--lockfile", lockfile]
        policy_argv.extend(common_flags)
        policy_argv.append("--")
        policy_argv.extend(cmd_tokens)
        
        policy_passed = True
        policy_stdout = ""
        policy_stderr = ""
        policy_error: MCPTrustCommandError | None = None
        
        try:
            policy_result = self._run(policy_argv, timeout=timeout)
            policy_stdout = policy_result.stdout
            policy_stderr = policy_result.stderr
        except MCPTrustCommandError as e:
            policy_passed = False
            policy_stdout = e.stdout
            policy_stderr = e.stderr
            policy_error = e
        
        passed = diff_passed and policy_passed
        
        if raise_on_fail and not passed:
            # Raise the first error encountered
            if diff_error:
                raise diff_error
            if policy_error:
                raise policy_error
        
        return CheckResult(
            passed=passed,
            diff_stdout=diff_stdout,
            diff_stderr=diff_stderr,
            policy_stdout=policy_stdout,
            policy_stderr=policy_stderr,
        )
    
    def run(
        self,
        *,
        lockfile: str = "mcp-lock.json",
        require_provenance: bool = False,
        dry_run: bool = False,
        bin_name: str | None = None,
        timeout: int | None = None,
        log: LogConfig | None = None,
        receipt: ReceiptConfig | None = None,
        raise_on_fail: bool = True,
    ) -> RunResult:
        """Run from verified artifact."""
        argv = ["run", "--lock", lockfile]
        argv.extend(self._build_common_flags(log, receipt))
        
        if require_provenance:
            argv.append("--require-provenance")
        else:
            argv.append("--require-provenance=false")
        
        if dry_run:
            argv.append("--dry-run")
        
        if bin_name:
            argv.extend(["--bin", bin_name])
        
        try:
            result = self._run(argv, timeout=timeout)
            return RunResult(
                exit_code=0,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except MCPTrustCommandError as e:
            if raise_on_fail:
                raise
            return RunResult(
                exit_code=e.exit_code,
                stdout=e.stdout,
                stderr=e.stderr,
            )
    
    def version(self) -> str:
        """Get mcptrust version string."""
        result = self._run(["--version"])
        return result.stdout.strip()
