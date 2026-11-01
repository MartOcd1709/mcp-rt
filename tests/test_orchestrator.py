"""Assessment orchestrator: lifecycle sequencing over an injected base scan (no network).

Verifies scan findings flow into correlation + remediation, a proven chain elevates the verdict and
leads the remediation plan, and adaptive probes are PROPOSED (not counted as findings).
"""
from hunt import orchestrator as orch

_BASE = {
    "target": "npx -y demo-mcp",
    "verdict": "VULNERABLE",
    "findings": [
        {"cls": "path_traversal", "tool": "read_file", "sev": "High", "fix": "confine to root"},
        {"cls": "ssrf", "tool": "fetch", "sev": "High", "fix": "block internal hosts"},
    ],
    "surface": {"tools": [{"name": "read_file"}, {"name": "fetch"}]},
}


def test_assess_builds_chain_and_remediation():
    a = orch.assess("npx -y demo-mcp", base_report=_BASE)
    assert a.verdict == "VULNERABLE"
    # READ (path_traversal) + EGRESS (ssrf) -> credential-exfiltration chain
    assert any(c.kind == "credential_exfiltration" for c in a.chains)
    # chain-first remediation (P0), then per-finding fixes
    assert a.remediation[0]["priority"] == "P0" and a.remediation[0]["target"] == "chain"
    assert any(r["target"] == "finding" and r["cls"] == "path_traversal" for r in a.remediation)


def test_clean_server_no_chain_no_vuln():
    base = {"target": "x", "verdict": "CLEAN", "findings": [], "surface": {"tools": []}}
    a = orch.assess("x", base_report=base)
    assert a.verdict == "CLEAN" and a.chains == [] and a.remediation == []


def test_adaptive_proposes_probes_but_not_as_findings():
    a = orch.assess("x", base_report=_BASE, adaptive=True)
    assert len(a.candidates) >= 1                       # probes proposed for the target's tools
    assert all(c.target_tool in ("read_file", "fetch") for c in a.candidates)
    assert len(a.findings) == 2                          # findings unchanged — probes await validation


def test_persist_writes_asset_findings_and_chains(tmp_path):
    from hunt.findings_db import DB
    a = orch.assess("npx -y demo-mcp", base_report=_BASE)        # VULNERABLE, 2 findings, 1+ chain
    db = DB(tmp_path / "t.db")
    ids = orch.persist(a, db=db)
    assert ids["findings"] == 2 and ids["chains"] >= 1
    # the server is now an asset with a primary id; findings + chains attached to it
    assert db.conn.execute("SELECT name FROM targets WHERE id=?", (ids["target_id"],)).fetchone()["name"] == "npx -y demo-mcp"
    assert db.conn.execute("SELECT COUNT(*) c FROM findings WHERE target_id=?", (ids["target_id"],)).fetchone()["c"] == 2
    assert db.conn.execute("SELECT COUNT(*) c FROM chains WHERE target_id=?", (ids["target_id"],)).fetchone()["c"] >= 1
    db.close()


def test_as_dict_shape():
    d = orch.assess("x", base_report=_BASE).as_dict()
    assert set(d) >= {"target", "verdict", "findings", "chains", "remediation", "surface"}
    assert d["surface"]["tools"] == ["read_file", "fetch"]
