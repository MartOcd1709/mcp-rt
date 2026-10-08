"""Scan → relationship DB. The ONE write-path: a scan's results become backbone rows (server, tools,
granular findings, knowledge-graph patterns). `scan_target` stays pure — it returns results and never
touches the DB; persistence is this separate concern, called by the CLI / daily / report orchestrator.

This is what fills the graph that every SaaS view and the in-house model read from. A VULNERABLE finding
also writes an `attack_patterns` node — the labelled unit the model trains on later.
"""
from __future__ import annotations

from .findings_db import DB
from .report import CLASS_META, _target_name


def _sev(class_id: str) -> str:
    return CLASS_META.get(class_id, {}).get("sev", "")


def _cwe(class_id: str) -> str:
    return CLASS_META.get(class_id, {}).get("cwe", "")


def persist_scan(db: DB, argv: list[str], results, surface: dict | None = None, *,
                 mode: str = "scan", agent: str = "", evidence_path: str = "") -> int:
    """Persist one scan_target run. Returns the scan id. Idempotent on the target row; findings append.
    Call `db.seed_classes()` is handled here so findings' class_id FK always resolves."""
    db.seed_classes()
    name = _target_name(" ".join(argv))
    tid = db.add_target(name=name, install_cmd=" ".join(argv), source="scan")
    verdict = "VULNERABLE" if any(r.verdict == "VULNERABLE" for r in results) else "CLEAN"
    sid = db.add_scan(tid, mode=mode, verdict=verdict, agent=agent, evidence=evidence_path)

    if surface:                                   # the attack surface (tools + resources)
        for t in surface.get("tools", []):
            db.upsert_tool(tid, t.get("name", ""), kind="tool",
                           declared=",".join(t.get("params", []) or []))
        for r in surface.get("resources", []):
            if r:
                db.upsert_tool(tid, str(r), kind="resource")

    for r in results:                             # granular finding per (tool, class) + KG node
        cls = r.probe
        fid = db.add_finding(tid, scan_id=sid, class_id=cls, tool=r.tool, verdict=r.verdict,
                             severity=_sev(cls), marker=r.marker, evidence=r.evidence,
                             rationale=r.rationale)
        if r.verdict == "VULNERABLE":
            db.add_attack_pattern(class_id=cls, finding_id=fid, technique=r.rationale,
                                  payload=r.evidence, outcome=f"marker={r.marker}" if r.marker else "confirmed",
                                  cwe=_cwe(cls))
    return sid


def persist_supply(db: DB, argv_or_name, sc_findings) -> int | None:
    """Persist MCP04 static supply-chain findings (dicts from supply_chain.analyze_*) onto a target.
    Install-hook rows are ground-truth findings; unpinned rows are FLAG."""
    if not sc_findings:
        return None
    db.seed_classes()
    name = _target_name(" ".join(argv_or_name)) if isinstance(argv_or_name, list) else str(argv_or_name)
    tid = db.add_target(name=name, source="supply")
    for f in sc_findings:
        fid = db.add_finding(tid, class_id="supply_chain", tool="(package)", verdict=f["verdict"],
                             severity=f.get("severity", ""), evidence=f.get("evidence", ""),
                             rationale=f.get("rationale", ""))
        if f.get("ground_truth"):
            db.add_attack_pattern(class_id="supply_chain", finding_id=fid,
                                  technique=f.get("rationale", ""), payload=f.get("evidence", ""),
                                  outcome="install-time code execution", cwe="CWE-829")
    return tid


def _selftest():
    import tempfile
    from dataclasses import dataclass
    from pathlib import Path

    @dataclass
    class R:
        probe: str; tool: str; verdict: str; marker: str = ""; evidence: str = ""; rationale: str = ""

    db = DB(Path(tempfile.mkdtemp()) / "p.db")
    results = [R("command_injection", "run", "VULNERABLE", marker="sent-abc", evidence="; touch x",
                 rationale="injected ; executed"),
               R("ssrf", "fetch", "CLEAN", rationale="no internal sink reached")]
    surface = {"tools": [{"name": "run", "params": ["cmd"]}, {"name": "fetch", "params": ["url"]}],
               "resources": ["file:///a"]}
    sid = persist_scan(db, ["npx", "-y", "demo-mcp"], results, surface)
    # the vulnerable finding traverses to its server + class, and produced a KG node
    row = db.conn.execute(
        "SELECT t.name srv, f.verdict, c.cwe, c.title FROM findings f JOIN targets t ON t.id=f.target_id "
        "JOIN attack_classes c ON c.id=f.class_id WHERE f.verdict='VULNERABLE'").fetchone()
    assert row["srv"] == "demo-mcp" and row["cwe"] == "CWE-78", dict(row)
    assert db.conn.execute("SELECT COUNT(*) n FROM tools WHERE target_id IN "
                           "(SELECT id FROM targets WHERE name='demo-mcp')").fetchone()["n"] == 3
    assert db.conn.execute("SELECT COUNT(*) n FROM attack_patterns").fetchone()["n"] == 1
    # supply-chain install hook -> ground-truth finding + pattern
    persist_supply(db, "evil-pkg", [dict(verdict="VULNERABLE", ground_truth=True, severity="High",
                                         evidence="postinstall: node x.js", rationale="runs on install")])
    assert db.conn.execute("SELECT COUNT(*) n FROM attack_patterns WHERE class_id='supply_chain'").fetchone()["n"] == 1
    db.close()
    print("persist selftest OK")


if __name__ == "__main__":
    _selftest()
