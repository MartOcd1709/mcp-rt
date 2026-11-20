"""Harvest the model-facing text of REAL MCP servers into tests/data/real_manifests.json.

The tool-poisoning precision gate (tests/test_tool_poisoning.py) runs the detector over this file, so false positives
are measured on what real servers actually ship, not on sentences we wrote. Re-run when adding servers:

    python3 tests/data/harvest_real_manifests.py

Each server is launched locally from the package cache (the npx cache's own bin / uvx --offline), in a throwaway cwd, with a minimal
environment; only tools/list, resources/list, prompts/list and the initialize result are read. No tool is called.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

OUT = Path(__file__).with_name("real_manifests.json")
D = tempfile.mkdtemp(prefix="mcprt_harvest_")
NPM = [  # (package, extra args) - launched from the local npx cache by their own `bin`, never fetched
    ("@modelcontextprotocol/server-everything", []),
    ("@modelcontextprotocol/server-filesystem", [D]),
    ("@playwright/mcp", ["--headless"]),
    ("@dev.saqibaziz/mcp-pdf-reader", []),
    ("@m_sea_bass/relpath-filesystem-mcp", [D]),
    ("mcp-server-filesystem", [D]),
    ("mcp-server-filesystem-smart", [D]),
    ("metamcp-filesystem-server-downloads", [D]),
]


def _npm_argv(pkg: str, extra: list[str]) -> list[str] | None:
    roots = [*Path.home().glob(".npm/_npx/*/node_modules"), Path(__file__).resolve().parents[2] / ".trial/node_modules"]
    for root in roots:
        pj = root / pkg / "package.json"
        if pj.is_file():
            meta = json.loads(pj.read_text())
            b = meta.get("bin")
            b = b if isinstance(b, str) else next(iter((b or {}).values()), None)
            if b:
                return ["node", str((pj.parent / b).resolve()), *extra]
    return None


SERVERS = [(pkg, a) for pkg, extra in NPM if (a := _npm_argv(pkg, extra))] + [("mcp-atlassian", ["uvx", "--offline", "mcp-atlassian"])]
ENV = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "TMPDIR", "XDG_CACHE_HOME") if k in os.environ}
# mcp-atlassian needs a site to start; a closed loopback port is enough to list its tools (nothing is called)
# placeholder (not real) credentials against a closed local port: it only lists its tools when a site is configured
ENV.update({"JIRA_URL": "http://127.0.0.1:9", "JIRA_USERNAME": "harvest", "JIRA_API_TOKEN": "placeholder",
            "CONFLUENCE_URL": "http://127.0.0.1:9/wiki", "CONFLUENCE_USERNAME": "harvest", "CONFLUENCE_API_TOKEN": "placeholder"})


async def harvest(label: str, argv: list[str]) -> dict | None:
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=ENV, cwd=D)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await asyncio.wait_for(s.initialize(), 60)
            tools = (await asyncio.wait_for(s.list_tools(), 60)).tools
            out = {"server": label, "version": getattr(init.serverInfo, "version", ""),
                   "instructions": init.instructions or "",
                   "tools": [{"name": t.name, "title": getattr(t, "title", None) or "", "description": t.description or "",
                              "inputSchema": t.inputSchema or {},
                              "annotations": t.annotations.model_dump(exclude_none=True) if t.annotations else {}}
                             for t in tools],
                   "resources": [], "prompts": []}
            try:
                out["resources"] = [{"uri": str(x.uri), "name": x.name or "", "description": x.description or ""}
                                    for x in (await asyncio.wait_for(s.list_resources(), 30)).resources]
            except Exception:  # noqa: BLE001 - many servers expose no resources
                pass
            try:
                out["prompts"] = [{"name": p.name, "description": p.description or "",
                                   "arguments": [{"name": a.name, "description": a.description or ""} for a in (p.arguments or [])]}
                                  for p in (await asyncio.wait_for(s.list_prompts(), 30)).prompts]
            except Exception:  # noqa: BLE001
                pass
            return out


async def main() -> int:
    got = []
    for label, argv in SERVERS:
        if not shutil.which(argv[0]):
            print(f"skip {label}: {argv[0]} not installed")
            continue
        try:
            m = await asyncio.wait_for(harvest(label, argv), 120)
            got.append(m)
            print(f"ok   {label}: {len(m['tools'])} tools, {len(m['resources'])} resources, {len(m['prompts'])} prompts, "
                  f"instructions {len(m['instructions'])} chars")
        except Exception as e:  # noqa: BLE001 - one broken server must not stop the harvest
            print(f"FAIL {label}: {type(e).__name__}: {str(e)[:120]}")
    OUT.write_text(json.dumps(got, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT} ({sum(len(m['tools']) for m in got)} tools from {len(got)} servers)")
    shutil.rmtree(D, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
