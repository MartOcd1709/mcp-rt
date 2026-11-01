"""hunt-all end-to-end pipeline: discover -> assess each -> (HITL gate on non-local http) -> results.

Verifies target routing (stdio vs http), the loopback auto-authorization, and the HITL gate that
holds back a non-local http target unless --authorized-by is given.
"""
from dataclasses import dataclass

from hunt import pipeline as pl
from hunt.discover import DiscoveredServer


@dataclass
class _FakeAssessment:
    target: str
    verdict: str = "CLEAN"
    findings: list = None
    chains: list = None

    def __post_init__(self):
        self.findings = self.findings or []
        self.chains = self.chains or []


def _patch(monkeypatch, servers, remote_called):
    monkeypatch.setattr(pl._discover, "discover", lambda roots=None: list(servers))
    monkeypatch.setattr(pl._discover, "discover_localhost", lambda: [])
    monkeypatch.setattr(pl._orch, "assess",
                        lambda target, **kw: _FakeAssessment(target, verdict="VULNERABLE"))
    import hunt.remote
    monkeypatch.setattr(hunt.remote, "scan_remote",
                        lambda url, h, authz: remote_called.append((url, authz)) or
                        {"verdict": "CLEAN", "findings": [], "tools": []})


def test_stdio_server_is_assessed(monkeypatch):
    s = DiscoveredServer("fs", "cfg", "stdio", "npx -y @mcp/fs /tmp")
    _patch(monkeypatch, [s], [])
    results, skipped = pl.hunt_all(localhost=False, save=False)
    assert len(results) == 1 and results[0][1].verdict == "VULNERABLE"
    assert skipped == []


def test_non_local_http_is_gated_without_authorization(monkeypatch):
    s = DiscoveredServer("remote", "cfg", "http", "https://evil.example.com/mcp")
    remote_called = []
    _patch(monkeypatch, [s], remote_called)
    results, skipped = pl.hunt_all(localhost=False, save=False)        # no authorized_by
    assert results == [] and len(skipped) == 1
    assert "authorized-by" in skipped[0][1].lower()
    assert remote_called == []                                        # never touched the host


def test_non_local_http_scanned_with_authorization(monkeypatch):
    s = DiscoveredServer("remote", "cfg", "http", "https://cust.example.com/mcp")
    remote_called = []
    _patch(monkeypatch, [s], remote_called)
    results, skipped = pl.hunt_all(localhost=False, save=False,
                                   authorized_by="Jane, Acme, ticket-42")
    assert len(results) == 1 and remote_called[0][1] == "Jane, Acme, ticket-42"


def test_loopback_http_assessed_without_explicit_authorization(monkeypatch):
    s = DiscoveredServer("local", "probe", "http", "http://127.0.0.1:3001/sse")
    remote_called = []
    _patch(monkeypatch, [s], remote_called)
    results, skipped = pl.hunt_all(localhost=False, save=False)        # loopback = own machine
    assert len(results) == 1 and remote_called[0][1] == "localhost (own machine)"
