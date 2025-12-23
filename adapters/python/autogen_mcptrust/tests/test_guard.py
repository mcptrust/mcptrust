"""Unit tests for MCPTrustGuard."""

from unittest.mock import MagicMock, patch

import pytest


class TestMCPTrustGuard:
    """Tests for MCPTrustGuard class."""
    
    @pytest.fixture
    def mock_mcp(self):
        """Create a mock MCPTrust instance."""
        mcp = MagicMock()
        mcp.lock.return_value = MagicMock(
            lockfile_path="mcp-lock.json",
            stdout="locked",
            stderr="",
        )
        mcp.check.return_value = MagicMock(
            passed=True,
            diff_stdout="",
            diff_stderr="",
            policy_stdout="",
            policy_stderr="",
        )
        return mcp
    
    def test_requires_command_or_argv(self, mock_mcp):
        """Guard requires either server_command or server_argv."""
        from autogen_mcptrust import MCPTrustGuard
        
        with pytest.raises(ValueError, match="Must specify server_command or server_argv"):
            MCPTrustGuard(mcp=mock_mcp)
    
    def test_accepts_server_command(self, mock_mcp):
        """Guard accepts server_command string."""
        from autogen_mcptrust import MCPTrustGuard
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="npx -y server",
        )
        
        assert guard.server_command == "npx -y server"
        assert guard.server_argv is None
    
    def test_accepts_server_argv(self, mock_mcp):
        """Guard accepts server_argv list."""
        from autogen_mcptrust import MCPTrustGuard
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_argv=["npx", "-y", "server"],
        )
        
        assert guard.server_argv == ["npx", "-y", "server"]
        assert guard.server_command is None
    
    def test_prefers_argv_when_both_provided(self, mock_mcp):
        """Guard prefers server_argv when both are provided."""
        from autogen_mcptrust import MCPTrustGuard
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="ignored command",
            server_argv=["npx", "-y", "preferred"],
        )
        
        assert guard.server_argv == ["npx", "-y", "preferred"]
        assert guard.server_command is None
    
    def test_stores_config(self, mock_mcp):
        """Guard stores all configuration."""
        from autogen_mcptrust import MCPTrustGuard
        from mcptrust_core.types import LogConfig, ReceiptConfig
        
        log = LogConfig(format="jsonl", level="debug")
        receipt = ReceiptConfig(path="receipt.json")
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_argv=["npx", "server"],
            lockfile="custom.json",
            preset="strict",
            log=log,
            receipt=receipt,
        )
        
        assert guard.mcp is mock_mcp
        assert guard.lockfile == "custom.json"
        assert guard.preset == "strict"
        assert guard.log is log
        assert guard.receipt is receipt
    
    def test_lock_delegates_to_mcp(self, mock_mcp):
        """lock() calls MCPTrust.lock() with correct args."""
        from autogen_mcptrust import MCPTrustGuard
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="npx -y server",
            lockfile="test.json",
        )
        
        result = guard.lock(pin=True, verify_provenance=True)
        
        mock_mcp.lock.assert_called_once_with(
            "npx -y server",
            server_argv=None,
            lockfile="test.json",
            pin=True,
            verify_provenance=True,
            log=None,
            receipt=None,
        )
        assert result.lockfile_path == "mcp-lock.json"
    
    def test_check_delegates_to_mcp(self, mock_mcp):
        """check() calls MCPTrust.check() with correct args."""
        from autogen_mcptrust import MCPTrustGuard
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_argv=["npx", "-y", "server"],
            lockfile="test.json",
            preset="strict",
        )
        
        result = guard.check()
        
        mock_mcp.check.assert_called_once_with(
            None,
            server_argv=["npx", "-y", "server"],
            lockfile="test.json",
            preset="strict",
            log=None,
            receipt=None,
            raise_on_fail=False,
        )
        assert result.passed is True
    
    def test_check_default_non_throwing(self, mock_mcp):
        """check() defaults to non-throwing (raise_on_fail=False)."""
        from autogen_mcptrust import MCPTrustGuard
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="npx server",
        )
        
        guard.check()
        
        call_kwargs = mock_mcp.check.call_args.kwargs
        assert call_kwargs.get("raise_on_fail") is False
    
    def test_check_raise_on_fail_propagates(self, mock_mcp):
        """check(raise_on_fail=True) propagates to MCPTrust."""
        from autogen_mcptrust import MCPTrustGuard
        from mcptrust_core.errors import MCPTrustCommandError
        
        mock_mcp.check.side_effect = MCPTrustCommandError(
            "check failed",
            exit_code=1,
            argv=["mcptrust", "check"],
        )
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="npx server",
        )
        
        with pytest.raises(MCPTrustCommandError):
            guard.check(raise_on_fail=True)
        
        call_kwargs = mock_mcp.check.call_args.kwargs
        assert call_kwargs.get("raise_on_fail") is True
    
    @patch("autogen_mcptrust.guard.os.path.exists")
    def test_ensure_runs_lock_when_missing(self, mock_exists, mock_mcp):
        """ensure() locks when lockfile is missing."""
        from autogen_mcptrust import MCPTrustGuard
        
        mock_exists.return_value = False
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="npx server",
            lockfile="mcp-lock.json",
        )
        
        guard.ensure(pin=True, verify_provenance=True)
        
        mock_exists.assert_called_once_with("mcp-lock.json")
        mock_mcp.lock.assert_called_once()
        mock_mcp.check.assert_called_once()
    
    @patch("autogen_mcptrust.guard.os.path.exists")
    def test_ensure_skips_lock_when_exists(self, mock_exists, mock_mcp):
        """ensure() skips lock when lockfile exists."""
        from autogen_mcptrust import MCPTrustGuard
        
        mock_exists.return_value = True
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="npx server",
        )
        
        guard.ensure()
        
        mock_mcp.lock.assert_not_called()
        mock_mcp.check.assert_called_once()
    
    @patch("autogen_mcptrust.guard.os.path.exists")
    def test_ensure_skips_lock_when_disabled(self, mock_exists, mock_mcp):
        """ensure(lock_if_missing=False) never locks."""
        from autogen_mcptrust import MCPTrustGuard
        
        mock_exists.return_value = False
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="npx server",
        )
        
        guard.ensure(lock_if_missing=False)
        
        # Should not even check if file exists when lock_if_missing=False
        mock_mcp.lock.assert_not_called()
        mock_mcp.check.assert_called_once()
    
    @patch("autogen_mcptrust.guard.os.path.exists")
    def test_ensure_returns_check_result(self, mock_exists, mock_mcp):
        """ensure() returns CheckResult from check()."""
        from autogen_mcptrust import MCPTrustGuard
        
        mock_exists.return_value = True
        
        guard = MCPTrustGuard(
            mcp=mock_mcp,
            server_command="npx server",
        )
        
        result = guard.ensure()
        
        assert result.passed is True
