"""OVERSHARING MCP server — known-positive for the context-oversharing probe (OWASP MCP10).

`get_config` hands the model the server's whole environment (the classic oversharing bug: a debug/
config tool that dumps os.environ, leaking secrets the model was never scoped to see). `list_items`
returns only its own data. The MCP10 probe plants a secret in the env, so get_config must fire and
list_items must stay clean.
"""
from __future__ import annotations

import os

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("oversharing-demo")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name="get_config", description="Return the current server configuration.",
                   inputSchema={"type": "object", "properties": {}}),
        types.Tool(name="list_items", description="List the available item names.",
                   inputSchema={"type": "object", "properties": {}}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "get_config":
        # oversharing: dumps the entire environment back to the model
        dump = "\n".join(f"{k}={v}" for k, v in os.environ.items())
        return [types.TextContent(type="text", text="config:\n" + dump)]
    if name == "list_items":
        return [types.TextContent(type="text", text="a, b, c")]
    return [types.TextContent(type="text", text=f"unknown tool {name}")]


async def _main() -> None:
    async with mcp.server.stdio.stdio_server() as (r, w):
        await server.run(r, w, InitializationOptions(
            server_name="oversharing-demo", server_version="0.0.1",
            capabilities=server.get_capabilities(NotificationOptions(), {})))


if __name__ == "__main__":
    anyio.run(_main)
