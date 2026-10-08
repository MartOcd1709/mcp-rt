"""Findings ledger for the MCP vulnerability hunt — one SQLite file, stdlib only.

Start here: local, free, zero infra, one file at ``hunt/findings.db``. Records EVERY
result (LEAKED, CLEAN, UNOBSERVABLE, INCONCLUSIVE, SKIPPED) so negatives are kept
honestly — a CLEAN server is citable evidence and feeds the dashboard's denominator.

The same columns migrate 1:1 to Postgres on a VPS later; nothing about the schema
changes, only the connection string.

    python -m hunt.findings_db                 # create/upgrade the db + run a self-check

    from hunt.findings_db import DB
    db = DB()
    tid = db.add_target(name="foo-mcp", repo_url="https://github.com/x/foo-mcp",
                        install_cmd="npx -y foo-mcp", source="mcpmarket", language="ts", stars=120)
    sid = db.add_scan(tid, mode="scan", verdict="LEAKED", agent="claude-code",
                      marker="HT-abc123", channel="http_post", destination="evil.example",
                      notes="server_side_workflow class")
    db.add_disclosure(tid, sid, status="reported", advisory_id="GHSA-xxxx",
                      cwe="CWE-88", cvss="7.8", url="https://...")
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "findings.db"

VERDICTS = {"LEAKED", "CLEAN", "UNOBSERVABLE_BY_DESIGN", "INCONCLUSIVE", "RESILIENT",
            "VULNERABLE", "SKIPPED", "SETUP_FAILED"}  # VULNERABLE = an impl-bug probe (hunt.probes) fired;
#                                                       SETUP_FAILED = target never ran (install/config/bad pkg)
DISCLOSURE_STATES = {"none", "draft", "reported", "triaged", "published", "patched", "duplicate"}
# Hunting-harness output (MCP-00 legs) lives HERE, apart from `scans`. A hypothesis is a surfaced
# anomaly/lead — NEVER a finding, never counted as confirmed — until a planted canary fires and it is
# promoted to a VULNERABLE scan row. This separation is what keeps stats.json / the scorecard honest.
HYPOTHESIS_STATES = {"open", "confirmed", "dismissed", "promoted"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    repo_url    TEXT,
    install_cmd TEXT,                       -- the exact --target-stdio command
    source      TEXT,                       -- mcpmarket / registry / github
    language    TEXT,
    stars       INTEGER,
    added_at    REAL NOT NULL,
    UNIQUE(name, repo_url)
);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER NOT NULL REFERENCES targets(id),
    scanned_at  REAL NOT NULL,
    mode        TEXT NOT NULL,              -- scan / corpus / manual
    verdict     TEXT NOT NULL,              -- see VERDICTS
    agent       TEXT,                       -- claude-code / codex / n/a
    marker      TEXT,                       -- HT- value if leaked
    channel     TEXT,                       -- http_post / dns / ...
    destination TEXT,                       -- undeclared host the secret reached
    evidence    TEXT,                       -- path to a report/evidence json
    notes       TEXT
);
CREATE TABLE IF NOT EXISTS disclosures (
    id           INTEGER PRIMARY KEY,
    target_id    INTEGER NOT NULL REFERENCES targets(id),
    scan_id      INTEGER REFERENCES scans(id),
    status       TEXT NOT NULL DEFAULT 'none',   -- see DISCLOSURE_STATES
    advisory_id  TEXT,                            -- GHSA / CVE id
    cwe          TEXT,
    cvss         TEXT,
    url          TEXT,
    reported_at  REAL,
    published_at REAL,
    notes        TEXT
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id            INTEGER PRIMARY KEY,
    target_id     INTEGER NOT NULL REFERENCES targets(id),
    leg           TEXT NOT NULL,              -- mcp-cap / intent-flow / protocol / chain
    tool          TEXT,                       -- the tool the anomaly was observed on
    observation   TEXT NOT NULL,              -- what the server did that it shouldn't have
    confirmable   INTEGER NOT NULL DEFAULT 0, -- can the engine auto-confirm it end-to-end?
    confirm_plan  TEXT,                       -- how to turn it into ground truth
    caps_declared TEXT,                       -- JSON list (mcp-cap leg)
    caps_observed TEXT,                       -- JSON list (mcp-cap leg)
    status        TEXT NOT NULL DEFAULT 'open', -- see HYPOTHESIS_STATES
    scan_id       INTEGER REFERENCES scans(id), -- set when promoted to a confirmed VULNERABLE scan
    created_at    REAL NOT NULL,
    resolved_at   REAL,
    notes         TEXT,
    UNIQUE(target_id, leg, tool, observation)  -- re-runs don't pile duplicates
);
-- ---- The relationship backbone: what we scan -> what we find -> who it's for. ---------------
-- Additive to the ledger above; every SaaS view is a query over these. SQLite now, Postgres 1:1 later.
CREATE TABLE IF NOT EXISTS attack_classes (   -- the detection/hunt classes (mirrors report.CLASS_META)
    id        TEXT PRIMARY KEY,               -- e.g. command_injection, context_oversharing, supply_chain
    title     TEXT NOT NULL,
    cwe       TEXT,
    severity  TEXT,
    owasp     TEXT,                            -- comma-joined controls, e.g. "MCP05,MCP02"
    fix       TEXT
);
CREATE TABLE IF NOT EXISTS tools (            -- the attack surface each server exposes
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER NOT NULL REFERENCES targets(id),
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'tool',   -- tool | resource | prompt
    declared   TEXT,                           -- declared capabilities / description
    schema_json TEXT,
    UNIQUE(target_id, name, kind)
);
CREATE TABLE IF NOT EXISTS findings (         -- one verdict per (scan, tool, class) — granular, unlike scans
    id         INTEGER PRIMARY KEY,
    scan_id    INTEGER REFERENCES scans(id),
    target_id  INTEGER NOT NULL REFERENCES targets(id),
    class_id   TEXT REFERENCES attack_classes(id),
    tool       TEXT,
    verdict    TEXT NOT NULL,                  -- VULNERABLE | CLEAN | FLAG | INCONCLUSIVE
    severity   TEXT,
    marker     TEXT,                           -- the planted canary/sentinel that proved it (ground truth)
    evidence   TEXT,
    rationale  TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_patterns (  -- knowledge-graph node: the AI-training data moat
    id         INTEGER PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id),
    class_id   TEXT REFERENCES attack_classes(id),
    technique  TEXT,                           -- what was done
    payload    TEXT,                           -- the exact input/attack string
    outcome    TEXT,                           -- what the server did
    cwe        TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS chains (           -- composed multi-step attack (exploit-chain correlation)
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER NOT NULL REFERENCES targets(id),
    title      TEXT,
    severity   TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS chain_steps (
    chain_id   INTEGER NOT NULL REFERENCES chains(id),
    step_no    INTEGER NOT NULL,
    finding_id INTEGER REFERENCES findings(id),
    PRIMARY KEY(chain_id, step_no)
);
-- ---- The SaaS layer: who the findings are for. ----------------------------------------------
CREATE TABLE IF NOT EXISTS orgs (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_servers (    -- which servers belong to which org's fleet
    org_id     INTEGER NOT NULL REFERENCES orgs(id),
    target_id  INTEGER NOT NULL REFERENCES targets(id),
    PRIMARY KEY(org_id, target_id)
);
CREATE TABLE IF NOT EXISTS reports (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER REFERENCES orgs(id),
    target_id  INTEGER REFERENCES targets(id),
    title      TEXT,
    path       TEXT,                           -- generated PDF/HTML path
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS report_findings (
    report_id  INTEGER NOT NULL REFERENCES reports(id),
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    PRIMARY KEY(report_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
CREATE INDEX IF NOT EXISTS idx_hyp_status ON hypotheses(status);
CREATE INDEX IF NOT EXISTS idx_tools_target ON tools(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(class_id);
CREATE INDEX IF NOT EXISTS idx_patterns_class ON attack_patterns(class_id);
"""


class DB:
    def __init__(self, path: str | Path | None = None):
        # Resolve DB_PATH at call time (not as a default) so tests can monkeypatch the module attr.
        self.conn = sqlite3.connect(str(path if path is not None else DB_PATH))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def add_target(self, name: str, repo_url: str = "", install_cmd: str = "",
                   source: str = "", language: str = "", stars: int | None = None) -> int:
        """Insert a target (idempotent on name+repo_url). Returns its id."""
        self.conn.execute(
            "INSERT OR IGNORE INTO targets(name,repo_url,install_cmd,source,language,stars,added_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (name, repo_url, install_cmd, source, language, stars, time.time()))
        self.conn.commit()
        # Always resolve the real id by lookup — lastrowid is unreliable after INSERT OR IGNORE
        # when the row already existed (it returns a stale rowid, which breaks the FK on add_scan).
        row = self.conn.execute("SELECT id FROM targets WHERE name=? AND repo_url=?",
                                (name, repo_url)).fetchone()
        return row["id"]

    def add_scan(self, target_id: int, *, mode: str, verdict: str, agent: str = "",
                 marker: str = "", channel: str = "", destination: str = "",
                 evidence: str = "", notes: str = "") -> int:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict {verdict!r} not in {sorted(VERDICTS)}")
        cur = self.conn.execute(
            "INSERT INTO scans(target_id,scanned_at,mode,verdict,agent,marker,channel,"
            "destination,evidence,notes) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (target_id, time.time(), mode, verdict, agent, marker, channel,
             destination, evidence, notes))
        self.conn.commit()
        return cur.lastrowid

    def add_disclosure(self, target_id: int, scan_id: int | None = None, *,
                       status: str = "draft", advisory_id: str = "", cwe: str = "",
                       cvss: str = "", url: str = "", notes: str = "") -> int:
        if status not in DISCLOSURE_STATES:
            raise ValueError(f"status {status!r} not in {sorted(DISCLOSURE_STATES)}")
        now = time.time()
        cur = self.conn.execute(
            "INSERT INTO disclosures(target_id,scan_id,status,advisory_id,cwe,cvss,url,"
            "reported_at,notes) VALUES(?,?,?,?,?,?,?,?,?)",
            (target_id, scan_id, status, advisory_id, cwe, cvss, url,
             now if status in {"reported", "triaged", "published", "patched"} else None, notes))
        self.conn.commit()
        return cur.lastrowid

    def add_hypothesis(self, target_id: int, *, leg: str, observation: str, tool: str = "",
                       confirmable: bool = False, confirm_plan: str = "",
                       caps_declared: list | None = None, caps_observed: list | None = None,
                       status: str = "open", notes: str = "") -> int:
        """Record a hunting-harness lead. Idempotent on (target, leg, tool, observation) so a re-scan
        updates rather than duplicates. A hypothesis is NEVER a finding — see HYPOTHESIS_STATES."""
        if status not in HYPOTHESIS_STATES:
            raise ValueError(f"status {status!r} not in {sorted(HYPOTHESIS_STATES)}")
        self.conn.execute(
            "INSERT OR IGNORE INTO hypotheses(target_id,leg,tool,observation,confirmable,confirm_plan,"
            "caps_declared,caps_observed,status,created_at,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (target_id, leg, tool, observation, int(confirmable), confirm_plan,
             json.dumps(caps_declared or []), json.dumps(caps_observed or []),
             status, time.time(), notes))
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM hypotheses WHERE target_id=? AND leg=? AND tool=? AND observation=?",
            (target_id, leg, tool, observation)).fetchone()
        return row["id"]

    def resolve_hypothesis(self, hid: int, status: str, *, scan_id: int | None = None,
                           notes: str = "") -> None:
        """Move a hypothesis to confirmed/dismissed/promoted. `scan_id` links the VULNERABLE scan
        row it became, if promoted — that scan (not the hypothesis) is what counts as a finding."""
        if status not in HYPOTHESIS_STATES:
            raise ValueError(f"status {status!r} not in {sorted(HYPOTHESIS_STATES)}")
        self.conn.execute(
            "UPDATE hypotheses SET status=?, scan_id=?, resolved_at=?, notes=COALESCE(NULLIF(?,''),notes)"
            " WHERE id=?", (status, scan_id, time.time(), notes, hid))
        self.conn.commit()

    def open_hypotheses(self, leg: str | None = None) -> list[sqlite3.Row]:
        """Leads awaiting review/confirmation (for `mcp-rt hunt --hypotheses` and Ved's triage)."""
        q = ("SELECT h.*, t.name AS target FROM hypotheses h JOIN targets t ON t.id=h.target_id"
             " WHERE h.status='open'")
        params: tuple = ()
        if leg:
            q += " AND h.leg=?"
            params = (leg,)
        return self.conn.execute(q + " ORDER BY h.confirmable DESC, h.created_at DESC", params).fetchall()

    def seed_classes(self) -> int:
        """Populate attack_classes from the engine's class registry (report.CLASS_META). Idempotent."""
        from .report import CLASS_META  # deferred: report is higher-level than this ledger
        n = 0
        for cid, m in CLASS_META.items():
            self.conn.execute(
                "INSERT OR REPLACE INTO attack_classes(id,title,cwe,severity,owasp,fix) VALUES(?,?,?,?,?,?)",
                (cid, m.get("title", cid), m.get("cwe", ""), m.get("sev", ""),
                 ",".join(m.get("owasp", []) or []), m.get("fix", "")))
            n += 1
        self.conn.commit()
        return n

    def upsert_tool(self, target_id: int, name: str, *, kind: str = "tool",
                    declared: str = "", schema_json: str = "") -> int:
        """Record a tool/resource a server exposes (idempotent on target+name+kind)."""
        self.conn.execute(
            "INSERT OR IGNORE INTO tools(target_id,name,kind,declared,schema_json) VALUES(?,?,?,?,?)",
            (target_id, name, kind, declared, schema_json))
        self.conn.commit()
        return self.conn.execute("SELECT id FROM tools WHERE target_id=? AND name=? AND kind=?",
                                 (target_id, name, kind)).fetchone()["id"]

    def add_finding(self, target_id: int, *, verdict: str, class_id: str = "", tool: str = "",
                    scan_id: int | None = None, severity: str = "", marker: str = "",
                    evidence: str = "", rationale: str = "") -> int:
        """Record one granular finding (per scan×tool×class). A VULNERABLE row with a marker is the
        ground-truth unit the whole SaaS reports on."""
        cur = self.conn.execute(
            "INSERT INTO findings(scan_id,target_id,class_id,tool,verdict,severity,marker,evidence,"
            "rationale,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (scan_id, target_id, class_id or None, tool, verdict, severity, marker, evidence,
             rationale, time.time()))
        self.conn.commit()
        return cur.lastrowid

    def add_attack_pattern(self, *, class_id: str, finding_id: int | None = None, technique: str = "",
                           payload: str = "", outcome: str = "", cwe: str = "") -> int:
        """Record a knowledge-graph node for a confirmed attack — the labelled unit an in-house model
        trains on later. One per VULNERABLE finding."""
        cur = self.conn.execute(
            "INSERT INTO attack_patterns(finding_id,class_id,technique,payload,outcome,cwe,created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (finding_id, class_id or None, technique, payload, outcome, cwe, time.time()))
        self.conn.commit()
        return cur.lastrowid

    def tested_names(self, within_days: float | None = None) -> set[str]:
        """Names of targets already scanned (optionally only within the last `within_days`) —
        lets the daily run skip servers it has recently covered and grow the denominator."""
        q = "SELECT DISTINCT t.name FROM targets t JOIN scans s ON s.target_id=t.id"
        params: tuple = ()
        if within_days is not None:
            q += " WHERE s.scanned_at >= ?"
            params = (time.time() - within_days * 86400,)
        return {r["name"] for r in self.conn.execute(q, params).fetchall()}

    def summary(self) -> dict:
        """Dashboard numbers: counts per verdict + the honest denominator."""
        rows = self.conn.execute(
            "SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict").fetchall()
        by = {r["verdict"]: r["n"] for r in rows}
        tested = self.conn.execute("SELECT COUNT(DISTINCT target_id) n FROM scans").fetchone()["n"]
        leaked = self.conn.execute(
            "SELECT COUNT(DISTINCT target_id) n FROM scans WHERE verdict='LEAKED'").fetchone()["n"]
        # Open hunting leads — reported SEPARATELY so they can never be mistaken for confirmed findings.
        open_hyp = self.conn.execute(
            "SELECT COUNT(*) n FROM hypotheses WHERE status='open'").fetchone()["n"]
        return {"targets_tested": tested, "targets_leaked": leaked, "by_verdict": by,
                "open_hypotheses": open_hyp}

    def close(self):
        self.conn.close()


def _selftest() -> None:
    """Roundtrip the three tables in a temp db; assert the ledger stores and reads back."""
    import tempfile
    tmp = Path(tempfile.mkdtemp()) / "t.db"
    db = DB(tmp)
    tid = db.add_target(name="demo-mcp", repo_url="https://github.com/x/demo",
                        install_cmd="npx -y demo-mcp", source="mcpmarket", stars=42)
    assert db.add_target(name="demo-mcp", repo_url="https://github.com/x/demo") == tid, "not idempotent"
    sid = db.add_scan(tid, mode="scan", verdict="LEAKED", agent="claude-code",
                      marker="HT-deadbeef0000", channel="http_post", destination="evil.example")
    db.add_scan(tid, mode="scan", verdict="CLEAN", agent="codex")  # negative is recorded too
    db.add_disclosure(tid, sid, status="reported", advisory_id="GHSA-test", cwe="CWE-88", cvss="7.8")
    s = db.summary()
    assert s["targets_tested"] == 1 and s["targets_leaked"] == 1, s
    assert s["by_verdict"].get("LEAKED") == 1 and s["by_verdict"].get("CLEAN") == 1, s
    try:
        db.add_scan(tid, mode="scan", verdict="NONSENSE")
        raise AssertionError("bad verdict should have raised")
    except ValueError:
        pass
    db.close()
    print("findings_db self-check: ok", s)


if __name__ == "__main__":
    DB()  # create/upgrade the real db
    print(f"ready: {DB_PATH}")
    _selftest()
