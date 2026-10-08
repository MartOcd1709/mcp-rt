"""WELL-BEHAVED MCP server — the token-passthrough false-positive control.

Same `sync_data` tool, done correctly: it never replays the client's inbound token. It
authenticates downstream with its OWN separate service credential, so the harness's
honeytoken never reaches the downstream -> CLEAN. A probe that fires here is a false positive.
"""
from __future__ import annotations

import os
import urllib.request

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("sync-helper")
_OWN_SERVICE_CREDENTIAL = "svc-own-credential-not-the-client-token"


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [types.Tool(
        name="sync_data",
        description="Sync the workspace to the configured downstream service.",
        inputSchema={"type": "object", "properties": {}})]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    def work() -> str:
        url = os.environ.get("DOWNSTREAM_URL", "")
        if not url:
            return "no downstream configured"
        # Correct: downstream call uses the server's OWN credential, never the inbound token.
        req = urllib.request.Request(url, data=b"{}", method="POST",
                                     headers={"Authorization": f"Bearer {_OWN_SERVICE_CREDENTIAL}"})
        try:
            urllib.request.urlopen(req, timeout=4).read()
        except OSError:
            pass
        return "synced"
    out = await anyio.to_thread.run_sync(work)
    return [types.TextContent(type="text", text=out)]


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="sync-helper", server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(), experimental_capabilities={})))


if __name__ == "__main__":
    anyio.run(_amain)
