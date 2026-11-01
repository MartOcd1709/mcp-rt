"""#28 upstream-redirect SSRF oracle (sealed, black-box). Pins the four-outcome matrix on synthetic MCP
servers whose CONFIGURED upstream (env key UPSTREAM_URL) the probe points at a loopback sentinel. The
sealed recorder answers that sentinel with a 302 to an internal canary and records whether the server
FOLLOWS it (CVE-2026-77261 / mcp-atlassian <0.22.0 class):

  follows the 302 to the internal canary      -> VULNERABLE (oracle)
  fetches upstream, revalidates, blocks internal -> CLEAN   (oracle_negative)
  never calls the upstream                      -> INCONCLUSIVE (redirect_not_confirmed)
  upstream is https we cannot TLS-terminate     -> INCONCLUSIVE (redirect_not_confirmed)

Seal-gated: the oracle requires `unshare -rn`; where unavailable the parametrized cases skip (CI), and
the structural no-key case still runs.
"""
import sys

import pytest

from hunt.probes import verdict_for
from mcp_rt.runtime.runner import assess_redirect_follow
from tests.seal_capability import SEAL_REASON, can_seal

# One tool, "sync_upstream", whose behaviour toward its configured upstream (UPSTREAM_URL) is set by MODE.
SERVER = '''import asyncio, os, ssl, http.client, urllib.parse, urllib.request, urllib.error
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
MODE = __MODE__
srv = Server("rrgen")


class _NoInternal(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = urllib.parse.urlparse(newurl).hostname or ""
        if host in ("127.0.0.1", "localhost", "::1") or host.startswith(("10.", "192.168.", "169.254.")):
            raise urllib.error.HTTPError(newurl, code, "blocked internal redirect", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@srv.list_tools()
async def lt():
    return [types.Tool(name="sync_upstream", description="Fetch the configured upstream and return status.",
            inputSchema={"type": "object", "properties": {}})]


@srv.call_tool()
async def ct(name, args):
    url = os.environ.get("UPSTREAM_URL", "")
    try:
        if MODE == "follows":
            urllib.request.urlopen(url, timeout=3)                          # follows the 302 by default
        elif MODE == "revalidate":
            urllib.request.build_opener(_NoInternal).open(url, timeout=3)   # refuses an internal redirect target
        elif MODE == "https_only":
            u = urllib.parse.urlparse(url)
            c = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=3,
                                            context=ssl._create_unverified_context())
            c.request("GET", "/"); c.getresponse()                          # TLS to the sentinel -> no plaintext 302
        # MODE == "no_config": never touches the upstream at all
        out = "done"
    except Exception as e:
        out = "err: " + str(e)[:60]
    return [types.TextContent(type="text", text=out)]


async def main():
    async with stdio_server() as (r, w):
        await srv.run(r, w, srv.create_initialization_options())

asyncio.run(main())
'''

CASES = [
    ("follows", "oracle", "VULNERABLE"),
    ("revalidate", "oracle_negative", "CLEAN"),
    ("no_config", "redirect_not_confirmed", "INCONCLUSIVE"),
    ("https_only", "redirect_not_confirmed", "INCONCLUSIVE"),
]


def _run(mode, tmp_path):
    script = tmp_path / "rr_server.py"
    script.write_text(SERVER.replace("__MODE__", repr(mode)))
    return assess_redirect_follow([sys.executable, str(script)], upstream_keys=["UPSTREAM_URL"], timeout=60)


@pytest.mark.skipif(not can_seal(), reason=SEAL_REASON)
@pytest.mark.parametrize("mode,method,verdict", CASES, ids=[m for m, _, _ in CASES])
def test_redirect_follow_matrix(mode, method, verdict, tmp_path):
    res = _run(mode, tmp_path)
    assert (res["method"], res["verdict"]) == (method, verdict), \
        (mode, res["method"], res["verdict"], res.get("evidence"))


def test_no_upstream_key_is_inconclusive():
    """No configurable upstream (no RoE key) -> INCONCLUSIVE, never CLEAN. Structural; needs no seal."""
    res = assess_redirect_follow([sys.executable, "-c", "pass"], upstream_keys=[])
    assert res["verdict"] == "INCONCLUSIVE" and res["method"] == "redirect_not_confirmed"


def test_redirect_not_confirmed_is_inconclusive():
    assert verdict_for("redirect_not_confirmed") == "INCONCLUSIVE"


# ---- RoE field + agent-tier wiring --------------------------------------------------------------
def _roe(tmp_path, **over):
    import json
    doc = {"roe_version": 1, "target": {"id": "rr", "argv": ["echo", "hi"]},
           "classes": ["egress"], "authorized_by": "ved"}
    doc.update(over)
    p = tmp_path / "roe.json"
    p.write_text(json.dumps(doc))
    return p


def test_roe_parses_upstream_url_keys(tmp_path):
    from mcp_rt.agent_tier.roe import load_roe
    assert load_roe(_roe(tmp_path, upstream_url_keys=["UPSTREAM_URL", "BASE_URL"])).upstream_url_keys == \
        ["UPSTREAM_URL", "BASE_URL"]


def test_roe_defaults_empty_and_rejects_non_string(tmp_path):
    from mcp_rt.agent_tier.roe import RoEError, load_roe
    assert load_roe(_roe(tmp_path)).upstream_url_keys == []
    with pytest.raises(RoEError):
        load_roe(_roe(tmp_path, upstream_url_keys=[5]))


@pytest.mark.skipif(not can_seal(), reason=SEAL_REASON)
def test_assess_surfaces_redirect_ssrf(tmp_path):
    """End-to-end: a signed RoE with upstream_url_keys -> assess() runs the sealed redirect pass and
    surfaces report['redirect_ssrf'] (VULNERABLE on a follows-redirect server)."""
    import json
    from datetime import datetime, timedelta, timezone

    from mcp_rt.agent_tier.run import assess
    script = tmp_path / "rr_server.py"
    script.write_text(SERVER.replace("__MODE__", repr("follows")))
    roe = _roe(tmp_path, target={"id": "rr", "argv": [sys.executable, str(script)]},
               expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
               upstream_url_keys=["UPSTREAM_URL"])
    report = assess(str(roe))
    assert report.get("redirect_ssrf", {}).get("verdict") == "VULNERABLE", report.get("redirect_ssrf")
