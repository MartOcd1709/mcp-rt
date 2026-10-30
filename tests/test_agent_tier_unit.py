"""Agent tier, pure core — always runs (no seal, no model, no network).

Covers: RoE load/validate, the closed action space (T3 scope / T8 contract), planner determinism (T9),
ledger honesty (INCONCLUSIVE never folded into CLEAN; a VULNERABLE that did not reproduce is not proven),
and name-freedom of the tier code (T10).
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_rt.agent_tier.actions import ActionRejected, validate_action
from mcp_rt.agent_tier.ledger import Ledger
from mcp_rt.agent_tier.planner import DeterministicPlanner
from mcp_rt.agent_tier.roe import RoEError, load_roe, validate_for_run

REPO = Path(__file__).resolve().parents[1]
FUTURE = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
PAST = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()


def _write_roe(tmp, **over):
    target_file = tmp / "srv.py"
    target_file.write_text("print('x')\n")
    doc = {"roe_version": 1,
           "target": {"id": "lab", "argv": ["python3", str(target_file)]},
           "classes": ["command_injection", "egress"],
           "surface": {"tools": ["t1"]},
           "mode": "offline", "budget": {"max_actions": 5},
           "authorized_by": "ved", "expires_at": FUTURE}
    doc.update(over)
    p = tmp / "roe.json"
    p.write_text(json.dumps(doc))
    return p


# ---- RoE ---------------------------------------------------------------------------------------------
def test_roe_loads_and_clamps_budget_to_ceiling(tmp_path):
    p = _write_roe(tmp_path, budget={"max_actions": 99999, "max_wall_seconds": 99999})
    roe = load_roe(p)
    assert roe.budget.max_actions == 200 and roe.budget.max_wall_seconds == 3600   # code ceilings win


def test_roe_unsigned_expired_and_bad_mode_are_refused(tmp_path):
    with pytest.raises(RoEError):
        validate_for_run(load_roe(_write_roe(tmp_path, authorized_by="")))
    with pytest.raises(RoEError):
        validate_for_run(load_roe(_write_roe(tmp_path, expires_at=PAST)))
    with pytest.raises(RoEError):
        validate_for_run(load_roe(_write_roe(tmp_path, mode="banana")))


def test_roe_live_requires_optin_and_approval(tmp_path):
    p = _write_roe(tmp_path, mode="live")
    with pytest.raises(RoEError):                       # no --live opt-in
        validate_for_run(load_roe(p), allow_live=True)   # still missing approval fields
    p2 = _write_roe(tmp_path, mode="live", live_approved_by="ved", live_approved_at=FUTURE)
    with pytest.raises(RoEError):                       # approval present but no opt-in
        validate_for_run(load_roe(p2), allow_live=False)
    validate_for_run(load_roe(p2), allow_live=True)     # both -> ok


def test_roe_target_hash_mismatch_is_refused(tmp_path):
    p = _write_roe(tmp_path, target={"id": "lab", "argv": ["python3", str(tmp_path / "srv.py")],
                                     "sha256": "deadbeef"})
    with pytest.raises(RoEError):
        validate_for_run(load_roe(p))


# ---- closed action space (T3 scope, T8 contract) -----------------------------------------------------
def test_valid_actions_pass():
    a = validate_action({"action": "run_probe", "class": "command_injection", "tool": "t1", "reason": "x"},
                        classes=["command_injection"], tools=["t1"])
    assert a.kind == "run_probe" and a.cls == "command_injection" and a.tool == "t1"
    assert validate_action({"action": "stop", "reason": "objectives_exhausted"}, classes=[], tools=[]).kind == "stop"


@pytest.mark.parametrize("raw", [
    {"action": "shell", "command": "id"},                                   # not in the space
    {"action": "run_probe", "class": "command_injection", "tool": "t1", "verdict": "VULNERABLE"},  # verdict field
    {"action": "run_probe", "class": "command_injection", "tool": "t1", "payload": "x"},           # payload field
    {"action": "run_probe", "class": "ssrf", "tool": "t1"},                  # class not in RoE
    {"action": "run_probe", "class": "command_injection", "tool": "other"},  # tool not in surface
    {"action": "run_egress", "tool": "nope"},                               # tool not in surface
    {"action": "stop", "reason": "because"},                                # stop reason not in enum
    "not even a dict",
])
def test_out_of_space_or_scope_is_rejected(raw):
    with pytest.raises(ActionRejected):
        validate_action(raw, classes=["command_injection"], tools=["t1"])


# ---- planner determinism (T9) ------------------------------------------------------------------------
def test_deterministic_planner_is_reproducible():
    objs = [("run_probe", "command_injection", "t1"), ("run_egress", "egress", "t1")]
    seqs = []
    for _ in range(2):
        p = DeterministicPlanner(objs)
        seq = [p.next_action({}) for _ in range(4)]   # 2 objectives then stop, stop
        seqs.append(seq)
    assert seqs[0] == seqs[1]
    assert seqs[0][-1]["action"] == "stop" and seqs[0][0]["action"] == "run_probe"


# ---- ledger honesty ----------------------------------------------------------------------------------
def test_inconclusive_is_never_folded_into_clean():
    led = Ledger()
    led.record([{"class": "sql_injection", "tool": "t1", "method": "error", "verdict": "INCONCLUSIVE", "evidence": "x"}])
    led.record([{"class": "ssti", "tool": "t1", "method": "oracle_negative", "verdict": "CLEAN", "evidence": "y"}])
    rep = led.report()
    assert rep["coverage"]["cleared"] == 1 and rep["coverage"]["inconclusive"] == 1
    assert {r["class"] for r in rep["cleared"]} == {"ssti"}


def test_unreproduced_vulnerable_is_not_proven():
    led = Ledger()
    led.record([{"class": "command_injection", "tool": "t1", "method": "oracle", "verdict": "VULNERABLE", "evidence": "n"}])
    led.mark_reproduction("command_injection", "t1", reproduced=False, evidence="silent")
    rep = led.report()
    assert rep["proven"] == [] and rep["coverage"]["inconclusive"] == 1
    assert rep["inconclusive"][0]["method"] == "not_reproduced"


def test_reproduced_vulnerable_is_proven():
    led = Ledger()
    led.record([{"class": "command_injection", "tool": "t1", "method": "oracle", "verdict": "VULNERABLE", "evidence": "n"}])
    led.mark_reproduction("command_injection", "t1", reproduced=True)
    assert led.report()["coverage"]["flagged"] == 1


# ---- orchestration without a real seal (fail-closed + scope abort), via a faked session ---------------
def _fake_session(handle):
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _f(argv, **kw):
        yield handle
    return _f


class _FakeHandle:
    def __init__(self, *, sealed, tools=("t1",)):
        from types import SimpleNamespace
        self.sealed = sealed
        self.error = "seal denied" if not sealed else None
        self.integrity = None
        self._tools = [SimpleNamespace(name=n, description="", inputSchema={}) for n in tools]

    async def list_tools(self):
        return self._tools


def test_unproven_seal_marks_everything_inconclusive_and_never_probes(tmp_path, monkeypatch):
    import mcp_rt.agent_tier.run as run_mod
    monkeypatch.setattr(run_mod, "sealed_session", _fake_session(_FakeHandle(sealed=False)))
    rep = run_mod.assess(_write_roe(tmp_path, classes=["command_injection", "egress"],
                                    surface={"tools": ["t1", "t2"]}))
    assert rep["stop_reason"] == "ABORT_UNOBSERVABLE"
    assert rep["proven"] == [] and rep["cleared"] == []
    assert rep["coverage"]["inconclusive"] == rep["coverage"]["objectives"] > 0


def test_kill_switch_stops_before_any_action(tmp_path, monkeypatch):
    import mcp_rt.agent_tier.run as run_mod
    monkeypatch.setattr(run_mod, "sealed_session", _fake_session(_FakeHandle(sealed=True)))
    killfile = tmp_path / "STOP"
    killfile.write_text("stop")
    rep = run_mod.assess(_write_roe(tmp_path, classes=["command_injection"], surface={"tools": ["t1"]},
                                    kill_switch=str(killfile)))
    assert rep["stop_reason"] == "KILLED" and rep["coverage"]["actions_used"] == 0 and rep["proven"] == []


class _OutOfScopePlanner:
    name = "bad"

    def next_action(self, context):
        return {"action": "run_probe", "class": "ssrf", "tool": "t1"}   # ssrf not in the RoE classes


def test_repeated_out_of_scope_actions_abort_scope_without_executing(tmp_path, monkeypatch):
    import mcp_rt.agent_tier.run as run_mod
    monkeypatch.setattr(run_mod, "sealed_session", _fake_session(_FakeHandle(sealed=True)))
    # if any out-of-scope action reached execute(), the fake handle (no session) would blow up -> a clean
    # ABORT_SCOPE proves the validator stopped them first.
    rep = run_mod.assess(_write_roe(tmp_path, classes=["command_injection"], surface={"tools": ["t1"]}),
                         planner=_OutOfScopePlanner())
    assert rep["stop_reason"] == "ABORT_SCOPE"
    assert rep["coverage"]["scope_violations"] >= 3 and rep["proven"] == []


# ---- name-free (T10) ---------------------------------------------------------------------------------
def test_agent_tier_code_is_name_free():
    corpus = ["egress_evasion", "elicitation_prompt", "proxy_aggregator", "resource_content",
              "server_side_workflow", "tool_annotation", "tool_description_injection", "benign_invoice",
              "benign_routing", "benign_update_check", "vuln_server", "safe_server", "navigate_server",
              "gateway_call", "render_viewport", "import_from_url"]
    src = "".join(p.read_text() for p in (REPO / "mcp_rt" / "agent_tier").glob("*.py"))
    assert not [n for n in corpus if n in src]
