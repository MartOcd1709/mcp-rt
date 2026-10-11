"""Generate a disclosure-oriented assessment report (markdown) from the CMDB ledger.

Honest triage is built in. We report ground truth — and ground truth includes "this is by design".
Every finding carries a **disclosability** verdict so an operator never submits by-design behaviour
or our own test fixtures as a vulnerability (which would burn credibility with maintainers). Only a
reproduced, maintainer-triaged, non-by-design finding where a *restricted control is bypassed* is
disclosure-ready; those go through responsible disclosure (private first), never straight to public.
"""
from __future__ import annotations

import datetime
from pathlib import Path

_FIXTURE_HINTS = ("probe_fixtures", "vuln_server", "safe_server", "_fixtures")
_DEMO_HINTS = ("server-everything", "server-memory", "server-sequential", "server-time")


def triage(target: str, cls: str, tool: str) -> tuple[str, str]:
    """(disclosability, why). Conservative: default to REQUIRES TRIAGE, never auto-ready."""
    t = target.lower()
    if any(h in t for h in _FIXTURE_HINTS):
        return ("NOT FOR DISCLOSURE", "our own internal test fixture (deliberately vulnerable) — proves the engine, not a real target")
    if cls == "context_oversharing" and any(h in t for h in _DEMO_HINTS):
        return ("BY-DESIGN", "demo/reference server intentionally exposes environment/context (e.g. printEnv / get-env) — not a vulnerability")
    if cls == "ssrf" and ("fetch" in t or tool in ("fetch", "fetch_url", "fetch-url")):
        return ("LIKELY BY-DESIGN / FALSE-POSITIVE",
                "a fetch/HTTP tool fetching a URL is its declared purpose; a real issue only as a "
                "confused-deputy (the agent is tricked into an internal URL) — needs agent-tier "
                "confirmation. Also a probe-precision item: exclude declared fetch tools from SSRF.")
    return ("REQUIRES MAINTAINER TRIAGE",
            "verify it is NOT by-design, reproduce a minimal PoC, confirm a RESTRICTED control is "
            "bypassed (a non-executor made to execute / a confined tool escaping) before disclosure")


def _target_findings(db, mode: str = "assess", limit: int = 40) -> dict:
    rows = db.conn.execute(
        "SELECT t.name tname, s.id sid, s.verdict sverd, f.class_id cls, f.tool tool, f.severity sev, "
        "f.evidence ev, f.rationale rat, f.created_at ca "
        "FROM findings f JOIN targets t ON t.id=f.target_id JOIN scans s ON s.id=f.scan_id "
        "WHERE s.mode=? ORDER BY f.id DESC LIMIT ?", (mode, limit)).fetchall()
    out: dict = {}
    for r in rows:
        out.setdefault(r["tname"], []).append(dict(r))
    return out


def render(by_target: dict) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    L = [
        "# mcp-rt — MCP Server Security Assessment", "",
        f"*Generated {now} · ground-truth engine + alias2-mini adaptive proposals*", "",
        "> **Disclosure discipline.** This is a security assessment, not a submission packet. Each "
        "finding below carries a **Disclosability** verdict. Do **not** report anything marked "
        "*BY-DESIGN*, *FALSE-POSITIVE*, or *NOT FOR DISCLOSURE*. Only a finding marked ready after "
        "**maintainer triage + a reproduced PoC** goes through **responsible (private-first) "
        "disclosure**. Reporting by-design behaviour burns credibility.", "",
        "---", "",
    ]
    ready = 0
    for target, finds in by_target.items():
        L.append(f"## `{target}`")
        L.append("")
        for f in finds:
            disc, why = triage(target, f["cls"] or "", f["tool"] or "")
            if disc not in ("BY-DESIGN", "FALSE-POSITIVE", "LIKELY BY-DESIGN / FALSE-POSITIVE",
                            "NOT FOR DISCLOSURE"):
                ready += 1
            L += [
                f"### {f['cls']} — `{f['tool']}`  ·  severity: {f['sev'] or '—'}",
                f"- **Evidence (verified):** {f['ev'] or '(oracle fired; see rationale)'}",
                f"- **How it fired:** {f['rat'] or '—'}",
                f"- **Disclosability:** **{disc}** — {why}",
                "",
            ]
        L.append("")
    L += ["---", "",
          f"**Summary:** {sum(len(v) for v in by_target.values())} finding(s) across "
          f"{len(by_target)} server(s); **{ready} potentially disclosure-relevant** (still require "
          "maintainer triage + PoC). By-design / fixture / false-positive findings are excluded from "
          "that count by design.", "",
          "Real disclosures to date live in the ledger (`mcp-rt db`) and `disclosures/` — e.g. the "
          "CWE-22 and CWE-78 drafts from prior hunts. The path to more is the community-server hunt "
          "(`mcp-hunt` skill), triaged one by one.", ""]
    return "\n".join(L)


def write_report(out_path: str, *, db=None) -> str:
    from hunt.findings_db import DB
    close = db is None
    db = db or DB()
    try:
        text = render(_target_findings(db))
    finally:
        if close:
            db.close()
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return str(p)


def main(argv=None) -> int:
    import argparse
    import sys
    p = argparse.ArgumentParser(prog="mcp-rt assess-report",
                                description="Write a triaged assessment report (markdown) from the ledger")
    p.add_argument("--out", default=str(Path.home() / "Desktop" / "mcp-rt_assessment_report.md"))
    args = p.parse_args(argv)
    path = write_report(args.out)
    print(f"report written: {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
