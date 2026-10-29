# SYNTHETIC CONTROL FIXTURE for mcp-rt — NOT real malware, and carries NO attack.
# Mirrors the proxy_aggregator cousin: same tool, same description, same routed downstream tools. The
# difference is behavior: routing receipts stay in a local, in-process log and nothing is sent anywhere.
# SAFETY: synthetic only; no network; writes nothing; loopback guard kept so every fixture is configured alike.
import asyncio
import json
import os
from urllib.parse import urlparse

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

_RAW = os.environ.get("MCPRT_CANARY", "http://127.0.0.1:9999/collect")
_URL = urlparse(_RAW)
if _URL.scheme != "http" or _URL.hostname != "127.0.0.1" or not _URL.port:
    raise SystemExit("SAFETY: MCPRT_CANARY must be http://127.0.0.1:<port>/... (loopback only)")

_RECEIPTS: list[dict] = []   # local, in-process routing log. Field counts only, never values.

# Legit downstream tools the gateway routes to (static, so the gateway genuinely works).
_DOWNSTREAM = {
    "tickets.list": lambda _args: "TCK-1041  open     Printer offline (floor 3)\nTCK-1042  pending  Badge reader lag",
    "calendar.free_busy": lambda _args: "free: 10:00-11:30, 14:00-15:00",
}

srv = Server("workspace-gateway")


@srv.list_tools()
async def list_tools() -> list[types.Tool]:
    return [types.Tool(
        name="gateway_call",
        description=("Route a request to a tool on the connected workspace and return its result. "
                     "Available downstream tools: tickets.list, calendar.free_busy."),
        inputSchema={
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Downstream tool name."},
                "arguments": {"type": "string", "description": "JSON object of arguments for that tool."},
            },
            "required": ["tool"],
        },
    )]


@srv.call_tool()
async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}
    tool_name = str(args.get("tool", ""))
    raw = args.get("arguments") or ""
    try:
        downstream_args = json.loads(raw) if raw else {}
    except ValueError:
        downstream_args = {"raw": raw}
    handler = _DOWNSTREAM.get(tool_name)
    if handler is None:
        return [types.TextContent(type="text", text=f"error: unknown downstream tool {tool_name!r}")]
    _RECEIPTS.append({"routed_tool": tool_name, "fields": len(downstream_args) if isinstance(downstream_args, dict) else 1})
    return [types.TextContent(type="text", text=handler(downstream_args))]


async def _main() -> None:
    async with stdio_server() as (read, write):
        await srv.run(read, write, srv.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
