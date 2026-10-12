"""A small synchronous MCP client for the assessment agent to EXERCISE a target server.

The agent's depth comes from actually driving the target's MCP protocol surface — listing its tools
and resources and calling them with crafted inputs — not just running shell. MCP vulnerabilities live
exactly there (a path-traversal in a file tool, SSRF in a fetch tool, command injection in an exec
tool), so the agent needs a first-class way to reach them.

Scope: authorized, locally-launched stdio targets (the same way `mcp-rt scan`/`probe` already launch
and call them). Each call connects fresh, runs, and tears down — stateless and isolated per call.

ponytail: reconnect-per-call (stateless). If a stateful exploit needs set-then-get across calls, add a
persistent session; for independent probes this is simpler and cleaner to reason about.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _content_text(res) -> str:
    """Flatten an MCP CallToolResult / ReadResourceResult into readable text for the agent."""
    parts: list[str] = []
    if getattr(res, "isError", False):
        parts.append("[tool reported an error]")
    for attr in ("content", "contents"):
        for block in getattr(res, attr, None) or []:
            text = getattr(block, "text", None)
            if text:
                parts.append(text)
            elif getattr(block, "blob", None) is not None:
                parts.append(f"[blob {len(block.blob)} bytes]")
    return ("\n".join(parts))[:3000] or "[no content]"


class MCPClient:
    """Connect to an authorized stdio MCP target and call it. Methods are synchronous wrappers."""

    def __init__(self, target, *, env: dict | None = None, timeout: float = 30.0):
        self.argv = shlex.split(target) if isinstance(target, str) else list(target)
        self.env = env
        self.timeout = timeout

    def _run(self, fn):
        async def _session():
            workdir = tempfile.mkdtemp(prefix="mcprt_agent_")
            params = StdioServerParameters(command=self.argv[0], args=self.argv[1:],
                                           env={**(self.env or dict(os.environ))}, cwd=workdir)
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    return await fn(s)
        return asyncio.run(asyncio.wait_for(_session(), self.timeout))

    def list_tools(self) -> list[dict]:
        async def f(s):
            return [{"name": t.name, "description": (t.description or "")[:400],
                     "input_schema": getattr(t, "inputSchema", None)}
                    for t in (await s.list_tools()).tools]
        return self._run(f)

    def list_resources(self) -> list[dict]:
        async def f(s):
            try:
                return [{"uri": str(r.uri), "name": getattr(r, "name", "") or ""}
                        for r in (await s.list_resources()).resources]
            except Exception:  # noqa: BLE001 — server may not support resources
                return []
        return self._run(f)

    def call_tool(self, name: str, arguments: dict | None = None) -> str:
        async def f(s):
            return _content_text(await s.call_tool(name, arguments or {}))
        return self._run(f)

    def read_resource(self, uri: str) -> str:
        async def f(s):
            return _content_text(await s.read_resource(uri))
        return self._run(f)
