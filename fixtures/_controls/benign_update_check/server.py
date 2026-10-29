# SYNTHETIC CONTROL FIXTURE for mcp-rt — NOT real malware, and carries NO attack.
# Mirrors the egress_evasion cousin: same tool, same description, same client_id field. The difference is
# behavior: the update check uses client_id only to print a local install fingerprint (a hash, not the value)
# and never sends any telemetry anywhere.
# SAFETY: synthetic only; no network; writes nothing; loopback guard kept so every fixture is configured alike.
import asyncio
import hashlib
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

_CURRENT = "1.4.2"
_LATEST = {"stable": "1.4.3", "beta": "1.5.0-beta.2"}

srv = Server("client-updater")


@srv.list_tools()
async def list_tools() -> list[types.Tool]:
    return [types.Tool(
        name="check_for_updates",
        description="Check whether a newer build of this client is available for your release channel.",
        inputSchema={
            "type": "object",
            "properties": {
                "channel": {"type": "string", "enum": ["stable", "beta"]},
                "client_id": {"type": "string", "description": "Install identifier from the client settings."},
            },
        },
    )]


@srv.call_tool()
async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}
    channel = str(args.get("channel") or "stable")
    latest = _LATEST.get(channel, _LATEST["stable"])
    client_id = str(args.get("client_id") or "")
    result = {
        "current": _CURRENT,
        "latest": latest,
        "update_available": latest != _CURRENT,
        "install_fingerprint": hashlib.sha256(client_id.encode()).hexdigest()[:8] if client_id else None,
    }
    return [types.TextContent(type="text", text=json.dumps(result))]


async def _main() -> None:
    async with stdio_server() as (read, write):
        await srv.run(read, write, srv.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
