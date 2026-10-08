"""MCP10 context-oversharing probe — fires when a tool leaks the planted env secret to the model,
stays clean on a server that doesn't. Ground truth = a unique planted UUID, so zero false positives."""
import asyncio
import sys
from pathlib import Path

from hunt.probes import scan_target, probe_context_oversharing, VULNERABLE, CLEAN

FIX = Path(__file__).resolve().parent.parent / "hunt" / "probe_fixtures"


def _scan(server):
    return asyncio.run(scan_target([sys.executable, str(FIX / server)], probes=[probe_context_oversharing]))


def test_fires_on_env_dumping_tool():
    r = _scan("oversharing_server.py")
    vuln = [x for x in r if x.verdict == VULNERABLE]
    assert len(vuln) == 1 and vuln[0].tool == "get_config", r
    assert vuln[0].marker and vuln[0].marker.startswith("mcprt-ctx-")


def test_clean_server_does_not_overshare():
    # the well-behaved fixture has no env-dumping tool -> no planted secret reaches the model
    r = _scan("safe_server.py")
    assert all(x.verdict == CLEAN for x in r), [x for x in r if x.verdict == VULNERABLE]
