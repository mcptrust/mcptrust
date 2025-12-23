"""Unit tests for mcptrust_core.cli module."""

import os
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from mcptrust_core import MCPTrust, MCPTrustNotInstalled, MCPTrustCommandError
from mcptrust_core.types import LogConfig, ReceiptConfig


class TestBinaryDiscovery:
    """Tests for mcptrust binary discovery."""
    
    def test_explicit_bin_path(self):
        """bin_path argument takes precedence."""
        m = MCPTrust(bin_path="/custom/path/mcptrust")
        assert m.bin_path == "/custom/path/mcptrust"
    
    def test_env_var_discovery(self):
        """MCPTRUST_BIN env var is used when no bin_path."""
        with patch.dict(os.environ, {"MCPTRUST_BIN": "/env/mcptrust"}):
            with patch("shutil.which", return_value=None):
                m = MCPTrust()
                assert m.bin_path == "/env/mcptrust"
    
    def test_path_discovery(self):
        """Falls back to shutil.which when no env var."""
        with patch.dict(os.environ, {}, clear=True):
            # Make sure MCPTRUST_BIN is not set
            os.environ.pop("MCPTRUST_BIN", None)
            with patch("shutil.which", return_value="/usr/local/bin/mcptrust"):
                m = MCPTrust()
                assert m.bin_path == "/usr/local/bin/mcptrust"
    
    def test_not_installed_raises(self):
        """Raises MCPTrustNotInstalled when binary not found."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("MCPTRUST_BIN", None)
            with patch("shutil.which", return_value=None):
                with pytest.raises(MCPTrustNotInstalled):
                    MCPTrust()


class TestLockCommand:
    """Tests for MCPTrust.lock() method."""
    
    @pytest.fixture
    def mcp(self):
        """Create MCPTrust instance with mocked binary."""
        return MCPTrust(bin_path="/mock/mcptrust")
    
    def test_lock_builds_correct_argv_with_string(self, mcp):
        """lock() parses string command with shlex.split."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Locked successfully",
                stderr="",
            )
            
            result = mcp.lock("npx -y @scope/server /path")
            
            mock_run.assert_called_once()
            argv = mock_run.call_args[0][0]
            
            assert argv[0] == "/mock/mcptrust"
            assert "lock" in argv
            assert "--output" in argv
            assert "mcp-lock.json" in argv
            assert "--pin" in argv
            assert "--" in argv
            # shlex.split separates tokens
            dash_idx = argv.index("--")
            assert argv[dash_idx + 1] == "npx"
            assert argv[dash_idx + 2] == "-y"
            assert argv[dash_idx + 3] == "@scope/server"
            assert argv[dash_idx + 4] == "/path"
    
    def test_lock_with_server_argv(self, mcp):
        """lock() accepts server_argv for robust handling."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )
            
            mcp.lock(server_argv=["npx", "-y", "@scope/server", "/path with spaces"])
            
            argv = mock_run.call_args[0][0]
            dash_idx = argv.index("--")
            assert argv[dash_idx + 4] == "/path with spaces"  # preserved
    
    def test_lock_rejects_both_command_and_argv(self, mcp):
        """lock() rejects providing both server_command and server_argv."""
        with pytest.raises(ValueError, match="not both"):
            mcp.lock("cmd", server_argv=["cmd"])
    
    def test_lock_requires_command(self, mcp):
        """lock() requires either server_command or server_argv."""
        with pytest.raises(ValueError, match="Must specify"):
            mcp.lock()
    
    def test_lock_custom_lockfile(self, mcp):
        """lock() respects custom lockfile path."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )
            
            result = mcp.lock("cmd", lockfile="custom.json")
            
            argv = mock_run.call_args[0][0]
            assert "custom.json" in argv
            assert result.lockfile_path == "custom.json"
    
    def test_lock_with_provenance(self, mcp):
        """lock() adds --verify-provenance when requested."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )
            
            mcp.lock("cmd", verify_provenance=True)
            
            argv = mock_run.call_args[0][0]
            assert "--verify-provenance" in argv
    
    def test_lock_without_pin(self, mcp):
        """lock() omits --pin when pin=False."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )
            
            mcp.lock("cmd", pin=False)
            
            argv = mock_run.call_args[0][0]
            assert "--pin" not in argv


class TestCheckCommand:
    """Tests for MCPTrust.check() method."""
    
    @pytest.fixture
    def mcp(self):
        """Create MCPTrust instance with mocked binary."""
        return MCPTrust(bin_path="/mock/mcptrust")
    
    def test_check_runs_diff_then_policy(self, mcp):
        """check() runs both diff and policy commands."""
        calls = []
        
        def mock_run(argv, **kwargs):
            calls.append(argv)
            return MagicMock(returncode=0, stdout="", stderr="")
        
        with patch("subprocess.run", side_effect=mock_run):
            result = mcp.check("npx -y server")
            
            assert len(calls) == 2
            assert "diff" in calls[0]
            assert "policy" in calls[1]
            assert "check" in calls[1]
            assert result.passed is True
    
    def test_check_with_server_argv(self, mcp):
        """check() accepts server_argv."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            
            mcp.check(server_argv=["npx", "server"])
            
            # Both calls should have the argv
            assert mock_run.call_count == 2
    
    def test_check_uses_preset(self, mcp):
        """check() passes preset to policy command."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            
            mcp.check("cmd", preset="strict")
            
            # Second call is policy check
            policy_call = mock_run.call_args_list[1]
            argv = policy_call[0][0]
            assert "--preset" in argv
            assert "strict" in argv
    
    def test_check_fails_on_diff_error(self, mcp):
        """check() returns passed=False when diff fails."""
        call_count = [0]
        
        def mock_run(argv, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:  # diff
                return MagicMock(returncode=1, stdout="drift", stderr="error")
            return MagicMock(returncode=0, stdout="", stderr="")
        
        with patch("subprocess.run", side_effect=mock_run):
            result = mcp.check("cmd")
            
            assert result.passed is False
            assert "drift" in result.diff_stdout
    
    def test_check_fails_on_policy_error(self, mcp):
        """check() returns passed=False when policy fails."""
        call_count = [0]
        
        def mock_run(argv, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:  # policy
                return MagicMock(returncode=1, stdout="violation", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")
        
        with patch("subprocess.run", side_effect=mock_run):
            result = mcp.check("cmd")
            
            assert result.passed is False
            assert "violation" in result.policy_stdout
    
    def test_check_raise_on_fail(self, mcp):
        """check() raises MCPTrustCommandError when raise_on_fail=True."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="drift", stderr="err")
            
            with pytest.raises(MCPTrustCommandError):
                mcp.check("cmd", raise_on_fail=True)


class TestRunCommand:
    """Tests for MCPTrust.run() method."""
    
    @pytest.fixture
    def mcp(self):
        """Create MCPTrust instance with mocked binary."""
        return MCPTrust(bin_path="/mock/mcptrust")
    
    def test_run_builds_correct_argv(self, mcp):
        """run() builds correct argument vector."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            
            mcp.run(lockfile="my-lock.json")
            
            argv = mock_run.call_args[0][0]
            assert "run" in argv
            assert "--lock" in argv
            assert "my-lock.json" in argv
    
    def test_run_dry_run_flag(self, mcp):
        """run() adds --dry-run when requested."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            
            mcp.run(dry_run=True)
            
            argv = mock_run.call_args[0][0]
            assert "--dry-run" in argv
    
    def test_run_provenance_flag(self, mcp):
        """run() handles provenance flag correctly."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            
            mcp.run(require_provenance=True)
            
            argv = mock_run.call_args[0][0]
            assert "--require-provenance" in argv
    
    def test_run_raises_by_default(self, mcp):
        """run() raises MCPTrustCommandError by default on failure."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            
            with pytest.raises(MCPTrustCommandError) as exc_info:
                mcp.run()
            
            assert exc_info.value.exit_code == 1
    
    def test_run_returns_result_when_raise_on_fail_false(self, mcp):
        """run() returns RunResult when raise_on_fail=False."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=42, stdout="out", stderr="err")
            
            result = mcp.run(raise_on_fail=False)
            
            assert result.exit_code == 42
            assert result.stderr == "err"


class TestLoggingAndReceipts:
    """Tests for logging and receipt flag handling."""
    
    @pytest.fixture
    def mcp(self):
        """Create MCPTrust instance with mocked binary."""
        return MCPTrust(bin_path="/mock/mcptrust")
    
    def test_log_config_flags(self, mcp):
        """LogConfig adds correct flags."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            
            log = LogConfig(format="jsonl", level="debug", output="/var/log/mcp.log")
            mcp.lock("cmd", log=log)
            
            argv = mock_run.call_args[0][0]
            assert "--log-format" in argv
            assert "jsonl" in argv
            assert "--log-level" in argv
            assert "debug" in argv
            assert "--log-output" in argv
            assert "/var/log/mcp.log" in argv
    
    def test_receipt_config_flags(self, mcp):
        """ReceiptConfig adds correct flags."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            
            receipt = ReceiptConfig(path="/receipts/r.json", mode="append")
            mcp.lock("cmd", receipt=receipt)
            
            argv = mock_run.call_args[0][0]
            assert "--receipt" in argv
            assert "/receipts/r.json" in argv
            assert "--receipt-mode" in argv
            assert "append" in argv


class TestErrorHandling:
    """Tests for error handling."""
    
    @pytest.fixture
    def mcp(self):
        """Create MCPTrust instance with mocked binary."""
        return MCPTrust(bin_path="/mock/mcptrust")
    
    def test_nonzero_exit_raises_command_error(self, mcp):
        """Non-zero exit raises MCPTrustCommandError with details."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="some output",
                stderr="error message",
            )
            
            with pytest.raises(MCPTrustCommandError) as exc_info:
                mcp.lock("cmd")
            
            err = exc_info.value
            assert err.exit_code == 1
            assert "some output" in err.stdout
            assert "error message" in err.stderr
            assert "/mock/mcptrust" in err.argv[0]
    
    def test_command_error_str_representation(self):
        """MCPTrustCommandError has useful string representation."""
        err = MCPTrustCommandError(
            "test error",
            exit_code=42,
            argv=["mcptrust", "lock"],
            stdout="out",
            stderr="err",
        )
        s = str(err)
        assert "test error" in s
        assert "42" in s
        assert "err" in s


# Optional integration test - only runs when env var is set
@pytest.mark.skipif(
    os.environ.get("MCPTRUST_INTEGRATION") != "1",
    reason="Integration tests require MCPTRUST_INTEGRATION=1",
)
class TestIntegration:
    """Integration tests requiring actual mcptrust binary."""
    
    def test_version_command(self):
        """Can run mcptrust --version."""
        m = MCPTrust()
        version = m.version()
        assert "mcptrust" in version.lower() or len(version) > 0
