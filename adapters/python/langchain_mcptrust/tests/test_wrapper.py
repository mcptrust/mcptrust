"""Unit tests for langchain_mcptrust package."""

from unittest.mock import MagicMock, patch

import pytest


class TestTrustedMCPServer:
    """Tests for TrustedMCPServer class."""
    
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
        mcp.run.return_value = MagicMock(
            exit_code=0,
            stdout="running",
            stderr="",
        )
        return mcp
    
    def test_init_stores_config(self, mock_mcp):
        """TrustedMCPServer stores configuration."""
        from langchain_mcptrust import TrustedMCPServer
        
        server = TrustedMCPServer(
            mcp=mock_mcp,
            server_command="npx -y server",
            lockfile="custom.json",
            preset="strict",
        )
        
        assert server.mcp is mock_mcp
        assert server.server_command == "npx -y server"
        assert server.lockfile == "custom.json"
        assert server.preset == "strict"
    
    def test_init_with_server_argv(self, mock_mcp):
        """TrustedMCPServer accepts server_argv."""
        from langchain_mcptrust import TrustedMCPServer
        
        server = TrustedMCPServer(
            mcp=mock_mcp,
            server_argv=["npx", "-y", "server"],
        )
        
        assert server.server_argv == ["npx", "-y", "server"]
        assert server.server_command is None
    
    def test_lock_calls_mcptrust(self, mock_mcp):
        """lock() delegates to MCPTrust.lock()."""
        from langchain_mcptrust import TrustedMCPServer
        
        server = TrustedMCPServer(
            mcp=mock_mcp,
            server_command="npx -y server",
            lockfile="test.json",
        )
        
        result = server.lock(verify_provenance=True)
        
        mock_mcp.lock.assert_called_once_with(
            "npx -y server",
            server_argv=None,
            lockfile="test.json",
            pin=True,
            verify_provenance=True,
            timeout=None,
            log=None,
            receipt=None,
        )
        assert result.lockfile_path == "mcp-lock.json"
    
    def test_check_calls_mcptrust(self, mock_mcp):
        """check() delegates to MCPTrust.check()."""
        from langchain_mcptrust import TrustedMCPServer
        
        server = TrustedMCPServer(
            mcp=mock_mcp,
            server_command="npx -y server",
            lockfile="test.json",
            preset="strict",
        )
        
        result = server.check()
        
        mock_mcp.check.assert_called_once_with(
            "npx -y server",
            server_argv=None,
            lockfile="test.json",
            preset="strict",
            timeout=None,
            log=None,
            receipt=None,
            raise_on_fail=False,
        )
        assert result.passed is True
    
    def test_run_calls_mcptrust(self, mock_mcp):
        """run() delegates to MCPTrust.run()."""
        from langchain_mcptrust import TrustedMCPServer
        
        server = TrustedMCPServer(
            mcp=mock_mcp,
            server_command="npx -y server",
            lockfile="test.json",
        )
        
        result = server.run(dry_run=True)
        
        mock_mcp.run.assert_called_once_with(
            lockfile="test.json",
            require_provenance=False,
            dry_run=True,
            bin_name=None,
            timeout=None,
            log=None,
            receipt=None,
            raise_on_fail=True,
        )
        assert result.exit_code == 0
    
    def test_backward_compat_alias(self, mock_mcp):
        """MCPTrustServer alias works."""
        from langchain_mcptrust import MCPTrustServer, TrustedMCPServer
        
        assert MCPTrustServer is TrustedMCPServer


class TestToolsFromSchema:
    """Tests for tools_from_schema function."""
    
    def test_extracts_tools(self):
        """tools_from_schema extracts tool definitions."""
        from langchain_mcptrust import tools_from_schema
        
        schema = {
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file",
                    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                },
                {
                    "name": "write_file", 
                    "description": "Write to a file",
                },
            ]
        }
        
        tools = tools_from_schema(schema)
        
        assert len(tools) == 2
        assert tools[0]["name"] == "read_file"
        assert tools[0]["description"] == "Read a file"
        assert "path" in tools[0]["input_schema"]["properties"]
        assert tools[1]["name"] == "write_file"
    
    def test_empty_on_invalid_schema(self):
        """tools_from_schema returns empty list for invalid input."""
        from langchain_mcptrust import tools_from_schema
        
        assert tools_from_schema({}) == []
        assert tools_from_schema({"tools": "not a list"}) == []
        assert tools_from_schema("not a dict") == []
        assert tools_from_schema(None) == []
    
    def test_skips_invalid_tools(self):
        """tools_from_schema skips tools without name."""
        from langchain_mcptrust import tools_from_schema
        
        schema = {
            "tools": [
                {"name": "valid_tool"},
                {"description": "no name"},
                "not a dict",
                {"name": "another_valid"},
            ]
        }
        
        tools = tools_from_schema(schema)
        
        assert len(tools) == 2
        assert tools[0]["name"] == "valid_tool"
        assert tools[1]["name"] == "another_valid"
    
    def test_handles_input_schema_variants(self):
        """tools_from_schema handles both inputSchema and input_schema."""
        from langchain_mcptrust import tools_from_schema
        
        schema = {
            "tools": [
                {"name": "camel", "inputSchema": {"type": "object"}},
                {"name": "snake", "input_schema": {"type": "array"}},
            ]
        }
        
        tools = tools_from_schema(schema)
        
        assert tools[0]["input_schema"]["type"] == "object"
        assert tools[1]["input_schema"]["type"] == "array"
