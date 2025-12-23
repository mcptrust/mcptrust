"""Unit tests for mcptrust_core.errors module."""

import pytest

from mcptrust_core.errors import MCPTrustError, MCPTrustNotInstalled, MCPTrustCommandError


class TestMCPTrustError:
    """Tests for base exception."""
    
    def test_is_exception(self):
        """MCPTrustError is a proper Exception."""
        with pytest.raises(MCPTrustError):
            raise MCPTrustError("test")
    
    def test_message_preserved(self):
        """Message is preserved in exception."""
        err = MCPTrustError("custom message")
        assert str(err) == "custom message"


class TestMCPTrustNotInstalled:
    """Tests for MCPTrustNotInstalled exception."""
    
    def test_is_mcptrust_error(self):
        """MCPTrustNotInstalled inherits from MCPTrustError."""
        err = MCPTrustNotInstalled()
        assert isinstance(err, MCPTrustError)
    
    def test_default_message(self):
        """Default message includes installation hint."""
        err = MCPTrustNotInstalled()
        msg = str(err)
        assert "mcptrust binary not found" in msg
        assert "go install" in msg
    
    def test_custom_message(self):
        """Custom message overrides default."""
        err = MCPTrustNotInstalled("custom")
        assert str(err) == "custom"


class TestMCPTrustCommandError:
    """Tests for MCPTrustCommandError exception."""
    
    def test_is_mcptrust_error(self):
        """MCPTrustCommandError inherits from MCPTrustError."""
        err = MCPTrustCommandError("msg", exit_code=1, argv=[])
        assert isinstance(err, MCPTrustError)
    
    def test_attributes_stored(self):
        """All attributes are stored and accessible."""
        err = MCPTrustCommandError(
            "command failed",
            exit_code=42,
            argv=["mcptrust", "lock", "--pin"],
            stdout="stdout content",
            stderr="stderr content",
        )
        
        assert err.exit_code == 42
        assert err.argv == ["mcptrust", "lock", "--pin"]
        assert err.stdout == "stdout content"
        assert err.stderr == "stderr content"
    
    def test_str_includes_exit_code(self):
        """String representation includes exit code."""
        err = MCPTrustCommandError("msg", exit_code=7, argv=[])
        assert "7" in str(err)
    
    def test_str_includes_stderr_preview(self):
        """String representation includes stderr preview."""
        err = MCPTrustCommandError(
            "msg",
            exit_code=1,
            argv=[],
            stderr="this is the error output",
        )
        assert "this is the error output" in str(err)
    
    def test_str_truncates_long_stderr(self):
        """Long stderr is truncated in string representation."""
        long_stderr = "x" * 500
        err = MCPTrustCommandError(
            "msg",
            exit_code=1,
            argv=[],
            stderr=long_stderr,
        )
        s = str(err)
        assert "..." in s
        assert len(s) < len(long_stderr) + 100  # Some overhead for formatting
    
    def test_empty_stderr_no_crash(self):
        """Empty stderr doesn't cause issues."""
        err = MCPTrustCommandError("msg", exit_code=1, argv=[], stderr="")
        s = str(err)
        assert "msg" in s
