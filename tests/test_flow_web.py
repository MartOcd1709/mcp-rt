"""Phase B — the live flow API + SSE. A flow starts in the background, its persisted trace is
tenant-scoped, and the SSE tailer replays every step + a terminal verdict event. Engine stubbed
(fast, deterministic); a file-backed SQLite is shared across the worker thread and the request."""
import time

import pytest

from hunt.platform_db import Store
from hunt.webapp import _flow_sse, create_app
from mcp_rt.assessment import Assessment
from mcp_rt.oracle import Proof

TestClient = pytest.importorskip("starlette.testclient").TestClient


def _fake_engine(verdict, proven):
    def run(target, *, progress=None, **kw):
        for m in ("discovering surface…", "surface: 2 tool(s)", "generated 3 test point(s)",
                  "round 1: proving 3 point(s)…", f"round 1: +{len(proven)} PROVEN (total {len(proven)})"):
            if progress:
                progress(m)
        return Assessment(target=target, tools=[{"name": "t"}],
                          proven=[p.as_dict() for p in proven], chains=[], rounds=1,
                          points_tested=3, verdict=verdict, note="done")
    return run


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    import mcp_rt.assessment as asm
    proven = [Proof("read_doc", "path_traversal", True, "read /etc/passwd", "root:x:0:0", "path")]
    monkeypatch.setattr(asm, "run_assessment", _fake_engine("VULNERABLE", proven))
    store = Store(url=f"sqlite:///{tmp_path}/web.db")        # file-backed: shared across threads
    tok = store.ensure_default_org()
    return TestClient(create_app(store)), store, tok


def _wait_done(c, h, fid, tries=80):
    for _ in range(tries):
        r = c.get(f"/api/flow/{fid}", headers=h)
        if r.status_code == 200 and r.json()["flow"]["status"] in ("done", "error"):
            return r.json()
        time.sleep(0.1)
    raise AssertionError("flow did not finish in time")


def test_create_flow_runs_and_persists(ctx):
    c, store, tok = ctx
    h = {"Authorization": f"Bearer {tok}"}
    r = c.post("/api/flow", headers=h, json={"target": "python vuln.py", "tier": "basic"})
    assert r.status_code == 200
    fid = r.json()["flow_id"]
    data = _wait_done(c, h, fid)
    assert data["flow"]["verdict"] == "VULNERABLE"
    assert any(s["text"].startswith("PROVEN") and s["kind"] == "verdict" for s in data["steps"])


def test_sse_replays_steps_and_terminal_verdict(ctx):
    c, store, tok = ctx
    h = {"Authorization": f"Bearer {tok}"}
    fid = c.post("/api/flow", headers=h, json={"target": "python vuln.py"}).json()["flow_id"]
    _wait_done(c, h, fid)
    body = "".join(_flow_sse(store, fid))                    # flow is done -> generator drains + ends
    assert "event: step" in body
    assert "event: done" in body and "VULNERABLE" in body


def test_auth_required_to_start(ctx):
    c, _, _ = ctx
    assert c.post("/api/flow", json={"target": "python x.py"}).status_code == 401


def test_tenant_isolation(ctx):
    c, store, tok = ctx
    h = {"Authorization": f"Bearer {tok}"}
    fid = c.post("/api/flow", headers=h, json={"target": "python x.py"}).json()["flow_id"]
    _wait_done(c, h, fid)
    other = store.create_org("other-tenant")
    r = c.get(f"/api/flow/{fid}", headers={"Authorization": f"Bearer {other}"})
    assert r.status_code == 404                              # no cross-tenant read


def test_flow_page_served(ctx):
    c, _, _ = ctx
    r = c.get("/flow")
    assert r.status_code == 200 and "mcp-rt" in r.text and "EventSource" in r.text
