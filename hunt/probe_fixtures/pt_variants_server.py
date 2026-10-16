"""DELIBERATELY VULNERABLE path-traversal VARIANT server — the Tier-B generality battery for #45.

Tool and param names are DELIBERATELY NOVEL (blob_read/link_follow/decode_fetch/snap_capture/safe_open;
params target/loc/ref/dest/name) and appear NOWHERE in hunt/probes.py — proving the path_traversal
probe is FULLY DYNAMIC: it derives the root, payloads and oracle purely from the advertised surface,
with zero hardcoded tool/param names. Each tool carries ONE distinct CWE-22/23 variant; safe_open is
the confined control that must stay CLEAN (the anti-false-positive anchor).

NOT a real target. Local, offline; used only by tests/test_pt_variants.py.
"""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile
import urllib.parse

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("doc-vault")

ROOT = tempfile.mkdtemp(prefix="battery_root_")          # the server's managed root (advertised below)
with open(os.path.join(ROOT, "readme.txt"), "w") as _fh:
    _fh.write("in-root file")
atexit.register(lambda: shutil.rmtree(ROOT, ignore_errors=True))
SEP = os.sep


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    def s(p):
        return {"type": "object", "properties": {p: {"type": "string"}}, "required": [p]}
    return [
        types.Tool(name="allowed_dirs", description="List the directories this vault may access.",
                   inputSchema={"type": "object", "properties": {}}),
        types.Tool(name="blob_read", description="Read a blob from the vault by path.", inputSchema=s("target")),
        types.Tool(name="link_follow", description="Open an item stored in the vault.", inputSchema=s("loc")),
        types.Tool(name="decode_fetch", description="Fetch a vault document by its URL-style path.", inputSchema=s("ref")),
        types.Tool(name="snap_capture", description="Capture a screenshot and save it to a file.", inputSchema=s("dest")),
        types.Tool(name="safe_snap", description="Render a report image and save it to a file (confined).", inputSchema=s("out")),
        types.Tool(name="safe_open", description="Open a vault file (confined to the vault root).", inputSchema=s("name")),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    def work() -> str:
        if name == "allowed_dirs":
            return ROOT
        if name == "blob_read":                      # CVE-2025-53110 shape: realpath + prefix, NO separator check
            target = arguments["target"]
            if os.path.realpath(target).startswith(ROOT):   # '<root>_pt_x' passes (shares prefix) -> escapes
                return open(target, errors="replace").read()
            return "denied"
        if name == "link_follow":                    # CVE-2025-53109 shape: separator-aware check, but follows symlink
            loc = arguments["loc"]
            ap = os.path.normpath(os.path.abspath(loc))
            if ap == ROOT or ap.startswith(ROOT + SEP):      # sibling '<root>_pt' correctly rejected...
                return open(loc, errors="replace").read()    # ...but no realpath re-check -> in-root symlink escapes
            return "denied"
        if name == "decode_fetch":                   # decodes %2e%2e%2f AFTER a naive literal check -> encoded bypass
            ref = arguments["ref"]
            if ref.startswith("/") or ".." in ref or "\\" in ref:
                return "denied"
            return open(urllib.parse.unquote(ref), errors="replace").read()
        if name == "snap_capture":                   # output-file escape: writes generated content to any dest
            with open(arguments["dest"], "w") as fh:
                fh.write("PNGDATA")
            return "saved"
        if name == "safe_snap":                      # CONFINED output tool: basename-only -> cannot escape root
            with open(os.path.join(ROOT, os.path.basename(arguments["out"])), "w") as fh:
                fh.write("PNGDATA")
            return "saved (confined)"
        if name == "safe_open":                      # CONFINED control: realpath + separator-aware boundary
            name_p = arguments["name"]
            if os.path.realpath(name_p) == ROOT or os.path.realpath(name_p).startswith(ROOT + SEP):
                return open(name_p, errors="replace").read()
            return "denied: resolves outside the vault root"
        return "unknown tool"
    try:
        out = await anyio.to_thread.run_sync(work)
    except Exception as exc:  # noqa: BLE001
        out = f"error: {exc}"
    return [types.TextContent(type="text", text=str(out)[:4096])]


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="doc-vault", server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(), experimental_capabilities={})))


if __name__ == "__main__":
    anyio.run(_amain)
