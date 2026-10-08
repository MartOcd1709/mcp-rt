"""Family B — token passthrough / confused deputy probe (the VAPT auth layer).

The 2026 class every MCP security taxonomy now leads with (OWASP MCP01, CSA confused
deputy): a server that replays the client's bearer token verbatim to a downstream service,
or acts on a token whose audience is not itself. An honest server uses its OWN service
credential (or a token exchange) for downstream calls and never forwards the inbound token.

Ground truth via the OAuth harness: we mint a unique honeytoken bearer token, hand it to the
server as its auth, point its downstream base-URL at our sink, drive its tools, and check
whether our EXACT token reaches the downstream. A verbatim match = token passthrough,
zero false positive. Every run preserves a full evidence transcript to hunt/logs/.

    python -m hunt.family_b --selftest
    python -m hunt.family_b --target-stdio "npx some-mcp-server"

Guardrail: local, open-source servers only; synthetic token; loopback-only. Recall is
bounded by whether the server reads one of the harness's env var names (see OAuthHarness);
the harness + fixtures are the reusable, verified core.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from hunt.oauth_harness import OAuthHarness
from hunt.probes import VULNERABLE, _build_args

VERDICTS = {"VULNERABLE", "CLEAN", "INCONCLUSIVE"}


@dataclass
class TokenResult:
    verdict: str
    tools_called: list = field(default_factory=list)
    passthrough: list = field(default_factory=list)   # the offending captures
    transcript: dict = field(default_factory=dict)
    rationale: str = ""


async def probe_token_passthrough(argv: list[str], env: dict | None = None) -> TokenResult:
    workdir = tempfile.mkdtemp(prefix="mcprt_tok_")
    h = OAuthHarness().start()
    try:
        full_env = {**(env or dict(os.environ)), **h.env()}
        params = StdioServerParameters(command=argv[0], args=argv[1:], env=full_env, cwd=workdir)
        called: list[str] = []
        try:
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    for t in (await s.list_tools()).tools:
                        try:
                            await s.call_tool(t.name, _build_args(t, {}))
                            called.append(t.name)
                        except Exception:  # noqa: BLE001 — a failing call is not a finding
                            pass
        except Exception as exc:  # noqa: BLE001 — server never came up
            return TokenResult("INCONCLUSIVE", transcript=h.transcript(),
                               rationale=f"server did not run: {type(exc).__name__}: {str(exc)[:120]}")
        hits = h.passthrough_hits()
        verdict = VULNERABLE if hits else "CLEAN"
        rationale = ("server replayed the client's bearer token verbatim to a downstream "
                     f"service ({hits[0]['path']}) — token passthrough / confused deputy"
                     if hits else "client token was not forwarded to any downstream")
        return TokenResult(verdict, tools_called=called, passthrough=hits,
                           transcript=h.transcript(), rationale=rationale)
    finally:
        h.stop()
        shutil.rmtree(workdir, ignore_errors=True)


def write_report(target: str, result: TokenResult) -> str:
    """Preserve a complete evidence report (verdict + OAuth transcript) under hunt/logs/."""
    logs = Path(__file__).resolve().parent / "logs"
    logs.mkdir(exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in target)[:60] or "target"
    path = logs / f"{stamp}_familyB_{safe}.json"
    path.write_text(json.dumps({"probe": "token_passthrough", "target": target,
                                "scanned_at": stamp, **asdict(result)}, indent=2, default=str))
    return str(path)


def _selftest() -> bool:
    base = Path(__file__).resolve().parent / "family_b_fixtures"
    py = sys.executable
    vuln = asyncio.run(probe_token_passthrough([py, str(base / "vuln_oauth_server.py")]))
    safe = asyncio.run(probe_token_passthrough([py, str(base / "safe_oauth_server.py")]))
    print(f"  vuln_oauth_server  -> {vuln.verdict}   ({vuln.rationale})")
    print(f"  safe_oauth_server  -> {safe.verdict}   ({safe.rationale})")
    ok = vuln.verdict == VULNERABLE and safe.verdict == "CLEAN"
    print("family_b self-check:", "ok" if ok else "FAILED")
    return ok


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hunt.family_b", description="token passthrough / confused deputy probe")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--selftest", action="store_true")
    g.add_argument("--target-stdio", metavar="CMD")
    args = p.parse_args(argv)
    if args.selftest:
        return 0 if _selftest() else 1
    import shlex
    result = asyncio.run(probe_token_passthrough(shlex.split(args.target_stdio)))
    print(f"token_passthrough vs {args.target_stdio!r}: {result.verdict}")
    print(f"  {result.rationale}")
    print("  report:", write_report(args.target_stdio, result))
    return 1 if result.verdict == VULNERABLE else 0


if __name__ == "__main__":
    sys.exit(main())
