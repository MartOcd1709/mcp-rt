"""SSRF by-design precision, end to end through probe_ssrf (#22).

Confirms the Ved-signed matrix against real MCP servers driven by the actual probe (its own loopback sink):
  - a benign browser-navigation fixture whose job IS to reach the URL -> by_design / CLEAN (the FP guard);
  - the calibration vuln_server's real SSRF (a data-op 'import' that fetches) -> oracle / VULNERABLE (no
    recall regression);
  - a name-free summarize-the-URL server (case 3) -> oracle / VULNERABLE.
"""
import asyncio
import sys
from pathlib import Path

from hunt.probes import probe_ssrf, scan_target

FIX = Path(__file__).resolve().parents[1] / "hunt" / "probe_fixtures"

SUMMARIZE_SERVER = '''
from __future__ import annotations
import urllib.request
import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("doc-summarizer")

@server.list_tools()
async def list_tools():
    return [types.Tool(name="digest_link",
        description="Summarize the document at the given url into three bullet points.",
        inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]})]

@server.call_tool()
async def call_tool(name, arguments):
    def work():
        try:
            body = urllib.request.urlopen(arguments["url"], timeout=3).read().decode("utf-8", "replace")
        except Exception as exc:
            return f"[fetch error] {exc}"
        return "summary: " + body[:40]
    return [types.TextContent(type="text", text=await anyio.to_thread.run_sync(work))]

async def _amain():
    async with mcp.server.stdio.stdio_server() as (r, w):
        await server.run(r, w, InitializationOptions(server_name="doc-summarizer", server_version="0.0.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(),
                                                 experimental_capabilities={})))

if __name__ == "__main__":
    anyio.run(_amain)
'''


def _ssrf(argv):
    return asyncio.run(scan_target(argv, probes=[probe_ssrf]))


def test_navigate_fixture_comes_back_by_design_clean():
    rows = _ssrf([sys.executable, str(FIX / "navigate_server.py")])
    assert rows, "no ssrf result for the navigate fixture"
    r = next(x for x in rows if x.tool == "render_viewport")
    assert r.confirmation_method == "by_design" and r.verdict == "CLEAN", r.as_dict() if hasattr(r, "as_dict") else r


def test_calibration_real_ssrf_stays_vulnerable():
    rows = _ssrf([sys.executable, str(FIX / "vuln_server.py")])
    imp = [x for x in rows if x.tool == "import_from_url"]
    assert imp, "import_from_url produced no ssrf result"
    assert imp[0].confirmation_method == "oracle" and imp[0].verdict == "VULNERABLE", imp[0]


def test_summarize_url_is_still_ssrf(tmp_path):
    server = tmp_path / "summ_server.py"
    server.write_text(SUMMARIZE_SERVER)
    rows = _ssrf([sys.executable, str(server)])
    r = next((x for x in rows if x.tool == "digest_link"), None)
    assert r is not None and r.confirmation_method == "oracle" and r.verdict == "VULNERABLE", rows
