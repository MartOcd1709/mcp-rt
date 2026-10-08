"""Hypothesis store — hunting-harness leads live apart from findings and NEVER inflate the count."""
import json
import tempfile
from pathlib import Path

import pytest

from hunt.findings_db import DB
from hunt.hunt_cap import record_hypotheses, classify_gaps, CAP_READ, CAP_NETWORK


@pytest.fixture
def db():
    d = DB(Path(tempfile.mkdtemp()) / "t.db")
    yield d
    d.close()


def test_hypothesis_roundtrip_and_dedup(db):
    tid = db.add_target(name="foo-mcp")
    h1 = db.add_hypothesis(tid, leg="mcp-cap", tool="read_note", observation="undeclared network",
                           confirmable=True, confirm_plan="egress sink",
                           caps_declared=["read"], caps_observed=["read", "network"])
    # re-surfacing the SAME anomaly on a re-scan must not create a duplicate row
    h2 = db.add_hypothesis(tid, leg="mcp-cap", tool="read_note", observation="undeclared network")
    assert h1 == h2
    rows = db.open_hypotheses()
    assert len(rows) == 1
    assert json.loads(rows[0]["caps_observed"]) == ["read", "network"]


def test_hypotheses_never_counted_as_findings(db):
    tid = db.add_target(name="foo-mcp")
    db.add_hypothesis(tid, leg="mcp-cap", tool="x", observation="undeclared write")
    s = db.summary()
    assert s["open_hypotheses"] == 1
    # the lead must NOT show up as a leaked/vulnerable target
    assert s["targets_leaked"] == 0
    assert "VULNERABLE" not in s["by_verdict"] and "LEAKED" not in s["by_verdict"]


def test_resolve_promotes_and_closes(db):
    tid = db.add_target(name="foo-mcp")
    hid = db.add_hypothesis(tid, leg="mcp-cap", tool="x", observation="undeclared exec", confirmable=True)
    # confirmed end-to-end -> promote, linking the real VULNERABLE scan that now carries the finding
    sid = db.add_scan(tid, mode="hunt", verdict="VULNERABLE", notes="canary fired")
    db.resolve_hypothesis(hid, "promoted", scan_id=sid, notes="command_injection confirmed")
    assert db.open_hypotheses() == []          # no longer an open lead
    assert db.summary()["open_hypotheses"] == 0


def test_record_bridge_from_leg1(db):
    tid = db.add_target(name="foo-mcp")
    gaps = classify_gaps("read_note", {CAP_READ}, {CAP_READ, CAP_NETWORK})
    ids = record_hypotheses(db, tid, gaps)
    assert len(ids) == 1
    assert db.open_hypotheses()[0]["tool"] == "read_note"


def test_bad_status_rejected(db):
    tid = db.add_target(name="foo-mcp")
    with pytest.raises(ValueError):
        db.add_hypothesis(tid, leg="mcp-cap", observation="x", status="nonsense")


def test_record_flag_persists_leads_under_clean_target_name(monkeypatch, tmp_path):
    # `hunt-cap --record` should store leads against the package NAME (not the full npx command),
    # idempotently, in the hypotheses table — never inflating any finding count.
    import hunt.findings_db as fdb
    import hunt.hunt_cap as hc
    monkeypatch.setattr(fdb, "DB_PATH", tmp_path / "led.db")
    hyps = hc.classify_gaps("read_note", {hc.CAP_READ}, {hc.CAP_READ, hc.CAP_NETWORK})
    hc._record("npx -y some-mcp-server@1.2.3 /tmp/fs_allowed", hyps)

    d = fdb.DB()
    opens = d.open_hypotheses()
    assert len(opens) == 1 and opens[0]["target"] == "some-mcp-server@1.2.3"
    assert opens[0]["leg"] == "mcp-cap"
    assert d.summary()["targets_leaked"] == 0            # a lead is never a finding
    d.close()
