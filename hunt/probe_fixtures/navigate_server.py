"""SYNTHETIC calibration fixture for mcp-rt SSRF precision (#22) — NOT malware.

A benign browser-navigation tool whose DECLARED PURPOSE is to navigate to and load a caller-supplied URL.
Reaching any URL (including loopback) is by-design for such a tool, so the SSRF probe must return
by_design (CLEAN tier), not VULNERABLE — this fixture is the regression guard for that false-positive
class (found by dogfooding a browser-navigation MCP server). The tool name is deliberately not a token
in hunt/probes.py: the classifier must decide from the declared purpose, not a hardcoded name.

SAFETY: fetches only the URL it is explicitly given (loopback in tests); no secrets; stdio transport.
"""
from __future__ import annotations

import urllib.request

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("headless-browser")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [types.Tool(
        name="render_viewport",
        description="Navigate the headless browser to the given url and return the loaded page contents.",
        inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]})]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    def work() -> str:
        try:
            return urllib.request.urlopen(arguments["url"], timeout=3).read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 — a load failure is still an observation
            return f"[navigation error] {exc}"
    text = await anyio.to_thread.run_sync(work)
    return [types.TextContent(type="text", text=text)]


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (r, w):
        await server.run(r, w, InitializationOptions(
            server_name="headless-browser", server_version="0.0.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(),
                                                 experimental_capabilities={})))


if __name__ == "__main__":
    anyio.run(_amain)
