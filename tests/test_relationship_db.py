"""The relationship backbone: server -> tool -> finding -> class, seeded class registry, fleet link.
Proves the schema builds and a finding traverses to its server, tool, and class."""
import tempfile
from pathlib import Path

import pytest

from hunt.findings_db import DB


@pytest.fixture
def db():
    d = DB(Path(tempfile.mkdtemp()) / "rel.db")
    yield d
    d.close()


def test_class_registry_seeds_from_engine(db):
    n = db.seed_classes()
    assert n >= 13   # 11 original + context_oversharing + supply_chain
    row = db.conn.execute("SELECT * FROM attack_classes WHERE id='context_oversharing'").fetchone()
    assert row["cwe"] == "CWE-200" and "MCP10" in row["owasp"]


def test_server_tool_finding_traversal(db):
    db.seed_classes()
    tid = db.add_target(name="foo-mcp", install_cmd="npx -y foo-mcp")
    db.upsert_tool(tid, "read_file", declared="read a file")
    assert db.upsert_tool(tid, "read_file") and len(
        db.conn.execute("SELECT 1 FROM tools WHERE target_id=?", (tid,)).fetchall()) == 1  # idempotent
    sid = db.add_scan(tid, mode="scan", verdict="VULNERABLE")
    fid = db.add_finding(tid, scan_id=sid, class_id="context_oversharing", tool="get_config",
                         verdict="VULNERABLE", marker="mcprt-ctx-abc", rationale="leaked env")
    # the finding joins back to its server and its class title
    row = db.conn.execute(
        "SELECT t.name AS server, f.tool, c.title AS cls, c.cwe FROM findings f "
        "JOIN targets t ON t.id=f.target_id JOIN attack_classes c ON c.id=f.class_id WHERE f.id=?",
        (fid,)).fetchone()
    assert row["server"] == "foo-mcp" and row["cls"].startswith("Context") and row["cwe"] == "CWE-200"


def test_saas_fleet_link(db):
    tid = db.add_target(name="foo-mcp")
    import time
    db.conn.execute("INSERT INTO orgs(name,created_at) VALUES('AcmeCorp',?)", (time.time(),))
    oid = db.conn.execute("SELECT id FROM orgs WHERE name='AcmeCorp'").fetchone()["id"]
    db.conn.execute("INSERT INTO fleet_servers(org_id,target_id) VALUES(?,?)", (oid, tid))
    db.conn.commit()
    row = db.conn.execute(
        "SELECT o.name FROM fleet_servers fs JOIN orgs o ON o.id=fs.org_id WHERE fs.target_id=?",
        (tid,)).fetchone()
    assert row["name"] == "AcmeCorp"
