"""WELL-BEHAVED MCP server — the false-positive control for the impl-bug probes.

Same three tools as vuln_server.py, each done correctly, so every probe must verdict CLEAN:
  * fetch_url — allowlists a single host; refuses anything else (no SSRF).
  * run_cmd   — no shell; fixed argv, argument passed as data (no injection).
  * read_doc  — resolves under a fixed root and rejects escapes (no traversal).

A probe that fires here is a false positive and must be fixed before it is trusted.
"""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import anyio
import yaml
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("doc-helper")
_ROOT = Path(tempfile.gettempdir()) / "safe_docs_root"
_ROOT.mkdir(exist_ok=True)
_ALLOWED_HOST = "example.com"

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE notes(id INTEGER, body TEXT)")
_db.execute("INSERT INTO notes VALUES (1, 'hello world')")
_db.commit()


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name="fetch_url", description="Fetch the contents of a URL.",
                   inputSchema={"type": "object", "properties": {"url": {"type": "string"}},
                                "required": ["url"]}),
        types.Tool(name="run_cmd", description="Run a diagnostic command and return its output.",
                   inputSchema={"type": "object", "properties": {"cmd": {"type": "string"}},
                                "required": ["cmd"]}),
        types.Tool(name="read_doc", description="Read a document from the workspace by path.",
                   inputSchema={"type": "object", "properties": {"path": {"type": "string"}},
                                "required": ["path"]}),
        types.Tool(name="restricted_cmd",
                   description="Run an allowlisted diagnostic command (find/grep/ls/tar only).",
                   inputSchema={"type": "object", "properties": {"cmd": {"type": "string"}},
                                "required": ["cmd"]}),
        types.Tool(name="write_doc", description="Write content to a document at the given path.",
                   inputSchema={"type": "object",
                                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                                "required": ["path", "content"]}),
        types.Tool(name="search_notes", description="Search the notes database by term.",
                   inputSchema={"type": "object", "properties": {"term": {"type": "string"}},
                                "required": ["term"]}),
        types.Tool(name="run_python", description="Execute a Python code snippet and return the result.",
                   inputSchema={"type": "object", "properties": {"code": {"type": "string"}},
                                "required": ["code"]}),
        types.Tool(name="render_message", description="Render a message template for the user.",
                   inputSchema={"type": "object", "properties": {"template": {"type": "string"}},
                                "required": ["template"]}),
        types.Tool(name="fetch_page", description="Fetch a web page via curl for the given URL.",
                   inputSchema={"type": "object", "properties": {"target": {"type": "string"}},
                                "required": ["target"]}),
        types.Tool(name="load_config", description="Load configuration from a YAML document.",
                   inputSchema={"type": "object", "properties": {"data": {"type": "string"}},
                                "required": ["data"]}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    def work() -> str:
        if name == "fetch_url":
            host = (urlparse(arguments["url"]).hostname or "").lower()
            if host != _ALLOWED_HOST:
                return "refused: host not allowlisted"
            return urllib.request.urlopen(arguments["url"], timeout=3).read().decode("utf-8", "replace")
        if name == "run_cmd":
            return subprocess.run(["echo", arguments["cmd"]], capture_output=True,
                                  text=True, timeout=5).stdout            # list form, no shell
        if name == "read_doc":
            target = (_ROOT / arguments["path"]).resolve()
            if not str(target).startswith(str(_ROOT.resolve()) + os.sep):  # confined
                return "refused: path escapes workspace root"
            return target.read_text(encoding="utf-8", errors="replace") if target.is_file() else "not found"
        if name == "restricted_cmd":                   # no shell + strict allowlist + metachar reject
            cmd = arguments["cmd"]
            if re.search(r"[;&|`$><\n()]", cmd) or (cmd.strip().split()[:1] != ["echo"]):
                return "refused: command not allowed"
            return subprocess.run(["echo", cmd], capture_output=True, text=True, timeout=5).stdout
        if name == "write_doc":                        # confined write
            target = (_ROOT / arguments["path"]).resolve()
            if not str(target).startswith(str(_ROOT.resolve()) + os.sep):
                return "refused: path escapes workspace root"
            target.write_text(arguments["content"])
            return "written"
        if name == "search_notes":                     # parameterised: term bound as data
            rows = _db.execute("SELECT body FROM notes WHERE body LIKE ?",
                               ("%" + arguments["term"] + "%",)).fetchall()
            return str(rows)
        if name == "run_python":                       # code execution disabled
            return "refused: code execution is disabled"
        if name == "render_message":                   # literal substitution, no evaluation
            return "Message: " + arguments["template"]
        if name == "fetch_page":                        # validates scheme + stops flag parsing with --
            t = arguments["target"]
            if t.startswith("-") or not t.startswith(("http://", "https://")):
                return "refused: invalid url"
            return subprocess.run(["curl", "-s", "--", t], capture_output=True,
                                  text=True, timeout=5).stdout or "(empty)"
        if name == "load_config":                       # safe deserialization: safe_load (no code exec)
            return str(yaml.safe_load(arguments["data"]))
        return f"unknown tool {name}"
    try:
        out = await anyio.to_thread.run_sync(work)
    except Exception as exc:  # noqa: BLE001
        out = f"error: {exc}"
    return [types.TextContent(type="text", text=out[:4096])]


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="doc-helper", server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(), experimental_capabilities={})))


if __name__ == "__main__":
    anyio.run(_amain)
