"""Official MCP Python SDK transport when the optional dependency is installed."""

from __future__ import annotations

import json
from typing import Any

from ovk.mcp_stdio import TOOL_HANDLERS


def _tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "structuredContent": payload,
    }


def serve_with_sdk() -> None:
    """Run OVK MCP tools using the official MCP Python SDK."""
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool

    server = Server("open-verification-kernel")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=name,
                description=f"Open Verification Kernel tool {name}",
                inputSchema={"type": "object", "additionalProperties": True},
            )
            for name in TOOL_HANDLERS
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        handler = TOOL_HANDLERS.get(name)
        if handler is None:
            raise ValueError(f"unknown tool: {name}")
        return _tool_result(handler(arguments or {}))

    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    import asyncio

    asyncio.run(_run())
