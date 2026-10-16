"""Phase A — the Flow backbone. Tests that a flow drives the engine, persists a complete
replayable step trace, and records the engine's verdict faithfully (no verdict invented here —
the oracle still decides; the flow only records). The engine is stubbed so this stays a fast
unit test of the flow layer; the real end-to-end is covered by the assessment/oracle tests."""
import json

from hunt.flow import _classify_step, run_flow
from hunt.platform_db import Store
from mcp_rt.assessment import Assessment
from mcp_rt.oracle import Proof


def _store(tmp_path):
    s = Store(url=f"sqlite:///{tmp_path}/flow.db")
    return s, s.org_for_token(s.ensure_default_org())


def _fake_engine(verdict, proven):
    def fake_run(target, *, progress=None, **kw):
        for m in ("discovering surface…", "surface: 3 tool(s)", "generated 5 test point(s)",
                  "round 1: proving 5 point(s)…", f"round 1: +{len(proven)} PROVEN "
                  f"(total {len(proven)})", "correlated 0 attack chain(s)"):
            if progress:
                progress(m)
        return Assessment(target=target, tools=[{"name": "t"}],
                          proven=[p.as_dict() for p in proven], chains=[], rounds=1,
                          points_tested=5, verdict=verdict,
                          note=f"{len(proven)} proven across 5 point(s)")
    return fake_run


def test_vulnerable_flow_persists_trace_and_verdict(tmp_path, monkeypatch):
    import mcp_rt.assessment as asm
    proven = [Proof("read_doc", "path_traversal", True, "read /etc/passwd", "root:x:0:0", "path"),
              Proof("run_cmd", "command_injection", True, "nonce echoed", "out", "cmd")]
    monkeypatch.setattr(asm, "run_assessment", _fake_engine("VULNERABLE", proven))
    store, org = _store(tmp_path)

    fid = run_flow(store, org, "python vuln_server.py")
    f = store.get_flow(fid)
    assert f["status"] == "done" and f["verdict"] == "VULNERABLE"
    steps = store.flow_steps(fid)
    assert len(steps) >= 8                                   # start + 6 progress + per-finding + report
    assert [s["seq"] for s in steps] == sorted(s["seq"] for s in steps)  # ordered trace
    # each proven finding has its own ground-truth verdict step
    proven_steps = [s for s in steps if s["kind"] == "verdict" and s["text"].startswith("PROVEN")]
    assert len(proven_steps) == 2 and all(s["phase"] == "prove" and s["role"] == "validation"
                                          for s in proven_steps)
    assert json.loads(f["summary"])["findings"] == 2


def test_clean_flow_has_no_false_findings(tmp_path, monkeypatch):
    import mcp_rt.assessment as asm
    monkeypatch.setattr(asm, "run_assessment", _fake_engine("CLEAN", []))   # safe server, nothing proven
    store, org = _store(tmp_path)
    fid = run_flow(store, org, "python safe_server.py")
    f = store.get_flow(fid)
    assert f["verdict"] == "CLEAN"
    assert not [s for s in store.flow_steps(fid) if s["text"].startswith("PROVEN")]  # zero-FP preserved
    assert json.loads(f["summary"])["findings"] == 0


def test_engine_error_is_recorded_not_raised(tmp_path, monkeypatch):
    import mcp_rt.assessment as asm

    def boom(target, *, progress=None, **kw):
        raise RuntimeError("target would not start")
    monkeypatch.setattr(asm, "run_assessment", boom)
    store, org = _store(tmp_path)
    fid = run_flow(store, org, "python nope.py")
    f = store.get_flow(fid)
    assert f["status"] == "error" and f["verdict"] == "ERROR"
    assert any("would not start" in s["text"] for s in store.flow_steps(fid))


def test_step_classification_maps_phases():
    assert _classify_step("discovering surface…")[0] == "discover"
    assert _classify_step("generated 5 test point(s)")[0] == "plan"
    assert _classify_step("round 1: +2 PROVEN (total 2)") == ("prove", "validation", "verdict")
    assert _classify_step("correlated 1 attack chain(s)")[0] == "correlate"
    assert _classify_step("something unmapped")[0] == ""


def test_list_and_isolation_by_org(tmp_path, monkeypatch):
    import mcp_rt.assessment as asm
    monkeypatch.setattr(asm, "run_assessment", _fake_engine("CLEAN", []))
    store, org = _store(tmp_path)
    run_flow(store, org, "python a.py")
    run_flow(store, org, "python b.py")
    assert len(store.list_flows(org)) == 2
    other = store.org_for_token(store.create_org("other-tenant"))
    assert store.list_flows(other) == []                     # tenancy: no cross-org leakage
