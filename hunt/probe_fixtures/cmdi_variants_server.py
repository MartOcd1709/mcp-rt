"""DELIBERATELY VULNERABLE command-injection VARIANT server — the Tier-B generality battery for #51.

Novel tool/param names (gated_run/open_shell/echo_guard/strict_run; param `instruction`/`cmd`) appear
NOWHERE in hunt/probes.py (the fully-dynamic gate). Cases:
  * gated_run   — secure-shell: allowlist INCLUDING an interpreter (/bin/bash) + metachar filter + naive
                  split -> the `<interp> -c <nonce>` carrier BYPASSES it; advertises "secure mode" -> VULNERABLE.
  * open_shell  — by-design unrestricted executor, desc says "Safely run any shell command" -> the benign
                  "safely" must NOT mis-class it; running a command is by-design -> CLEAN.
  * echo_guard  — rejects the payload but REFLECTS it (incl. the words "command not found") -> must be CLEAN
                  (no reflection false-positive: only the interpreter's OWN nonce-adjacent error counts).
  * strict_run  — refuses with a recognized deny -> CLEAN(refusal).

NOT a real target. Local, offline; used only by tests/test_cmdi_variants.py. It really runs /bin/bash on a
nonexistent command (harmless "not found") to produce a genuine interpreter error for the oracle.
"""
from __future__ import annotations

import subprocess

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("cmd-vault")

_ALLOWED = {"echo", "cat", "ls", "/bin/bash", "/usr/bin/python3"}   # note: an interpreter is allowlisted (the bug)
_META = set(";$()&|<>`{}[]\n")


def _run(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        return ((p.stdout or "") + (p.stderr or "")) or "(no output)"
    except Exception as exc:  # noqa: BLE001
        return f"exec error: {exc}"


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    def s(p):
        return {"type": "object", "properties": {p: {"type": "string"}}, "required": [p]}
    return [
        types.Tool(name="gated_run",
                   description="Run a command restricted to the allowed executables list (secure mode).",
                   inputSchema=s("instruction")),
        types.Tool(name="open_shell", description="Safely run any shell command and return its output.",
                   inputSchema=s("instruction")),
        types.Tool(name="echo_guard", description="Run a command after validating the request.",
                   inputSchema=s("instruction")),
        types.Tool(name="strict_run", description="Run an allowlisted diagnostic command.", inputSchema=s("cmd")),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    def work() -> str:
        if name == "gated_run":                      # secure-shell: metachar filter + naive split + allowlist
            instr = arguments["instruction"]
            if any(c in instr for c in _META):
                return "rejected: shell metacharacters not allowed in secure mode"
            parts = instr.split()
            if not parts or parts[0] not in _ALLOWED:
                return "Security violation: executable not in allowed list"
            return _run(parts)                        # BUG: /bin/bash is allowlisted -> `-c <nonce>` escapes
        if name == "open_shell":                     # by-design unrestricted executor (no restriction claim)
            return _run(["/bin/bash", "-c", arguments["instruction"]])
        if name == "echo_guard":                     # reject + REFLECT the payload (incl. "command not found")
            return f"error: command not found in the secure allowlist for request: {arguments['instruction']}"
        if name == "strict_run":                     # real refusal (recognized deny) unless an exact safe cmd
            if arguments["cmd"].strip() != "echo ok":
                return "Security violation: command not in the allowed list"
            return "ok"
        return "unknown tool"
    try:
        out = await anyio.to_thread.run_sync(work)
    except Exception as exc:  # noqa: BLE001
        out = f"error: {exc}"
    return [types.TextContent(type="text", text=str(out)[:4096])]


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="cmd-vault", server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(), experimental_capabilities={})))


if __name__ == "__main__":
    anyio.run(_amain)
