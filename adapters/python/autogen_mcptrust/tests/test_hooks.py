"""Unit tests for hook helpers."""

from unittest.mock import MagicMock, patch

import pytest


class TestEnsureTrustedMCPServer:
    """Tests for ensure_trusted_mcp_server function."""
    
    @patch("autogen_mcptrust.hooks.MCPTrustGuard")
    def test_constructs_guard_and_calls_ensure(self, MockGuard):
        """ensure_trusted_mcp_server creates guard and calls ensure."""
        from autogen_mcptrust import ensure_trusted_mcp_server
        
        mock_guard = MagicMock()
        mock_guard.ensure.return_value = MagicMock(passed=True)
        MockGuard.return_value = mock_guard
        
        result = ensure_trusted_mcp_server(
            server_argv=["npx", "server"],
            preset="strict",
        )
        
        MockGuard.assert_called_once_with(
            server_argv=["npx", "server"],
            preset="strict",
        )
        mock_guard.ensure.assert_called_once()
        assert result.passed is True
    
    @patch("autogen_mcptrust.hooks.MCPTrustGuard")
    def test_passes_all_kwargs_to_guard(self, MockGuard):
        """ensure_trusted_mcp_server passes all kwargs to guard constructor."""
        from autogen_mcptrust import ensure_trusted_mcp_server
        from mcptrust_core.types import LogConfig
        
        mock_guard = MagicMock()
        mock_guard.ensure.return_value = MagicMock(passed=True)
        MockGuard.return_value = mock_guard
        
        log = LogConfig(format="jsonl")
        
        ensure_trusted_mcp_server(
            server_command="npx server",
            lockfile="custom.json",
            log=log,
        )
        
        MockGuard.assert_called_once_with(
            server_command="npx server",
            lockfile="custom.json",
            log=log,
        )


class TestBeforeChatCallback:
    """Tests for before_chat_callback function."""
    
    def test_returns_callable(self):
        """before_chat_callback returns a callable."""
        from autogen_mcptrust import before_chat_callback
        
        mock_guard = MagicMock()
        callback = before_chat_callback(mock_guard)
        
        assert callable(callback)
    
    def test_callback_calls_guard_ensure(self):
        """Callback invokes guard.ensure()."""
        from autogen_mcptrust import before_chat_callback
        
        mock_guard = MagicMock()
        callback = before_chat_callback(mock_guard)
        
        callback()
        
        mock_guard.ensure.assert_called_once()
    
    def test_callback_passes_ensure_kwargs(self):
        """Callback passes kwargs to guard.ensure()."""
        from autogen_mcptrust import before_chat_callback
        
        mock_guard = MagicMock()
        callback = before_chat_callback(mock_guard, pin=True, verify_provenance=True)
        
        callback()
        
        mock_guard.ensure.assert_called_once_with(pin=True, verify_provenance=True)
    
    def test_callback_accepts_arbitrary_args(self):
        """Callback accepts *args/**kwargs for AutoGen compatibility."""
        from autogen_mcptrust import before_chat_callback
        
        mock_guard = MagicMock()
        callback = before_chat_callback(mock_guard)
        
        # Should not raise even with extra args
        callback("arg1", "arg2", extra_kwarg="value")
        
        mock_guard.ensure.assert_called_once()


class TestWrapRunner:
    """Tests for wrap_runner function."""
    
    def test_returns_callable(self):
        """wrap_runner returns a callable."""
        from autogen_mcptrust import wrap_runner
        
        mock_guard = MagicMock()
        wrapped = wrap_runner(lambda: None, mock_guard)
        
        assert callable(wrapped)
    
    def test_calls_ensure_before_fn(self):
        """Wrapper calls ensure before the original function."""
        from autogen_mcptrust import wrap_runner
        
        call_order = []
        
        mock_guard = MagicMock()
        mock_guard.ensure.side_effect = lambda **kw: call_order.append("ensure")
        
        def fn():
            call_order.append("fn")
            return "result"
        
        wrapped = wrap_runner(fn, mock_guard)
        result = wrapped()
        
        assert call_order == ["ensure", "fn"]
        assert result == "result"
    
    def test_passes_args_to_fn(self):
        """Wrapper passes arguments to the original function."""
        from autogen_mcptrust import wrap_runner
        
        mock_guard = MagicMock()
        
        def fn(a, b, c=None):
            return (a, b, c)
        
        wrapped = wrap_runner(fn, mock_guard)
        result = wrapped(1, 2, c=3)
        
        assert result == (1, 2, 3)
    
    def test_passes_ensure_kwargs_to_guard(self):
        """Wrapper passes ensure_kwargs to guard.ensure()."""
        from autogen_mcptrust import wrap_runner
        
        mock_guard = MagicMock()
        
        wrapped = wrap_runner(
            lambda: None,
            mock_guard,
            pin=False,
            raise_on_fail=False,
        )
        wrapped()
        
        mock_guard.ensure.assert_called_once_with(pin=False, raise_on_fail=False)
