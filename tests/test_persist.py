"""The scan -> relationship-DB write-path: a scan's results become server + tools + granular findings
+ knowledge-graph patterns, all traversable. Confirmed findings produce a KG node; clean ones don't."""
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from hunt.findings_db import DB
from hunt.persist import persist_scan, persist_supply


@dataclass
class R:
    probe: str
    tool: str
    verdict: str
    marker: str = ""
    evidence: str = ""
    rationale: str = ""


@pytest.fixture
def db():
    d = DB(Path(tempfile.mkdtemp()) / "p.db")
    yield d
    d.close()


def test_scan_fills_the_backbone(db):
    results = [R("command_injection", "run", "VULNERABLE", marker="s-1", evidence="; touch x",
                 rationale="injected"), R("ssrf", "fetch", "CLEAN", rationale="no sink")]
    surface = {"tools": [{"name": "run", "params": ["cmd"]}, {"name": "fetch", "params": ["url"]}],
               "resources": ["file:///a"]}
    persist_scan(db, ["npx", "-y", "demo-mcp"], results, surface)
    # finding traverses server -> class, with the right CWE
    row = db.conn.execute(
        "SELECT t.name srv, c.cwe FROM findings f JOIN targets t ON t.id=f.target_id "
        "JOIN attack_classes c ON c.id=f.class_id WHERE f.verdict='VULNERABLE'").fetchone()
    assert row["srv"] == "demo-mcp" and row["cwe"] == "CWE-78"
    # surface recorded (2 tools + 1 resource), and exactly one KG node (only the VULNERABLE finding)
    assert db.conn.execute("SELECT COUNT(*) n FROM tools").fetchone()["n"] == 3
    assert db.conn.execute("SELECT COUNT(*) n FROM attack_patterns").fetchone()["n"] == 1


def test_clean_scan_writes_no_pattern(db):
    persist_scan(db, ["npx", "-y", "clean-mcp"], [R("ssrf", "f", "CLEAN", rationale="ok")], {})
    assert db.conn.execute("SELECT COUNT(*) n FROM attack_patterns").fetchone()["n"] == 0
    assert db.summary()["targets_leaked"] == 0


def test_supply_chain_install_hook_persists_as_pattern(db):
    persist_supply(db, "evil-pkg", [dict(verdict="VULNERABLE", ground_truth=True, severity="High",
                                         evidence="postinstall: node x.js", rationale="runs on install")])
    n = db.conn.execute("SELECT COUNT(*) n FROM attack_patterns WHERE class_id='supply_chain'").fetchone()["n"]
    assert n == 1
