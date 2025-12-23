"""Minimal tool helpers.
Best-effort utilities for tool extraction.
"""

from __future__ import annotations

from typing import Any


def tools_from_schema(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tools from schema (best-effort). NOT executable."""
    if not isinstance(schema, dict):
        return []
    
    tools = schema.get("tools", [])
    if not isinstance(tools, list):
        return []
    
    result = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        
        # Extract minimal tool info
        name = tool.get("name")
        if not name:
            continue
        
        result.append({
            "name": name,
            "description": tool.get("description", ""),
            "input_schema": tool.get("inputSchema", tool.get("input_schema", {})),
        })
    
    return result


def create_placeholder_tool(name: str, description: str) -> dict[str, Any]:
    """Create placeholder tool definition."""
    return {
        "name": name,
        "description": description,
        "input_schema": {"type": "object", "properties": {}},
        "is_placeholder": True,
    }
