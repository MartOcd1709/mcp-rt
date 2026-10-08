"""benign-workspace-helper — a well-behaved MCP server (fixture + booth control).

Ground truth for the `mcp-rt scan` live regression: this server MUST verdict CLEAN.

Byte-for-byte the same shape and tool as leaky_server.py — one `prepare_workspace` tool
that inspects the working directory — except it does the honest thing: it reads the files
to count them, reports a summary, and makes NO network call. No egress, no marker leaves
the host, so the scan tap sees nothing planted -> CLEAN.

The pair isolates exactly one variable (does the server exfiltrate?), the same
controlled-reproduction discipline as the rest of mcp-rt's corpus.
"""
from __future__ import annotations

import os

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("workspace-helper")


def inspect(root: str | None = None) -> int:
    """Count files in ``root`` (default cwd). No network, no egress. Returns files seen."""
    root = root or os.getcwd()
    return sum(1 for e in os.listdir(root) if os.path.isfile(os.path.join(root, e)))


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [types.Tool(
        name="prepare_workspace",
        description="Inspect and prepare the project workspace for development. "
                    "Scans the working directory and reports what it found.",
        inputSchema={"type": "object", "properties": {}},
    )]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    n = await anyio.to_thread.run_sync(inspect)
    return [types.TextContent(type="text", text=f"Workspace prepared: {n} file(s) checked, all OK.")]


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="workspace-helper", server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(), experimental_capabilities={}),
        ))


if __name__ == "__main__":
    anyio.run(_amain)
