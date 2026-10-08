"""Graceful no-creds assessment: an auth failure is never scored CLEAN, execution-dependent classes get
marked REQUIRES_CREDENTIALS, and a server that won't start still runs the credential-free checks."""
import asyncio
import sys
from pathlib import Path

from hunt.probes import is_auth_error
from hunt.report import run_full_scan
from hunt.check import _run_full_check

FIX = Path(__file__).resolve().parent.parent / "hunt" / "probe_fixtures"


def test_is_auth_error_recognises_credential_failures():
    for t in ["401 Unauthorized", "Error: invalid API key", "authentication required",
              "permission denied", "403 Forbidden", "missing credentials", "you must log in"]:
        assert is_auth_error(t), t
    for t in ["file not found", "", "no such column", "sentinel created", "unrecognized token"]:
        assert not is_auth_error(t), t


def test_auth_gated_scan_marks_requires_credentials_not_clean(monkeypatch):
    # force the liveness check to report auth-gated, then confirm the report never scores
    # execution-dependent classes CLEAN/PASS (only surface/static classes stay trustworthy).
    import hunt.probes as probes

    async def fake_scan(argv, env=None, probes_=None, surface=None, **kw):
        if surface is not None:
            surface["tools"] = [{"name": "run", "params": ["cmd"]}]
            surface["resources"] = []
            surface["auth_gated"] = True
        return []  # no probe results (calls were auth-rejected)

    monkeypatch.setattr("hunt.report.scan_target", lambda *a, **k: fake_scan(*a, **k))

    from types import SimpleNamespace

    async def no_tok(argv, env=None):
        return SimpleNamespace(verdict="CLEAN", passthrough=None, transcript=[], rationale="n/a")
    monkeypatch.setattr("hunt.report.probe_token_passthrough", no_tok)

    rep = asyncio.run(run_full_scan(["npx", "-y", "needs-auth-mcp"]))
    assert rep["auth_gated"] is True
    # an execution-dependent control that saw no finding must be NOT TESTED, never PASS
    mcp05 = next(c for c in rep["compliance"] if c["id"] == "MCP05")
    assert mcp05["status"] == "NOT TESTED"
    # coverage for an exec-dependent clean class becomes REQUIRES_CREDENTIALS
    assert all(c["verdict"] != "CLEAN" or c["cls"] in ("tool_poisoning", "supply_chain")
               for c in rep["coverage"])


def test_server_that_wont_start_returns_inconclusive_not_crash():
    rc = _run_full_check(f"{sys.executable} {FIX / 'no_such_server_xyz.py'}", do_cap=False)
    assert rc == 2   # INCONCLUSIVE / needs creds — handled, not a crash
