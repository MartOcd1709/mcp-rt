"""Re-test / diff (A4) — re-scan a target and compare to its last recorded findings, reporting
RESOLVED / NEW / UNCHANGED. This is the "re-test after a fix" deliverable (Appsecco gives one re-test
per engagement; we give it on demand), and version-pinning means a re-scan of a bumped version is
compared against the prior version's findings by base package name.

    mcp-rt diff --target-stdio "npx -y some-mcp-server"
"""
from __future__ import annotations

import argparse
import asyncio
import re
import shlex
import sys

from hunt.findings_db import DB
from hunt.probes import ScanError
from hunt.report import _target_name, run_full_scan


def _base(name: str) -> str:
    """Strip a trailing @version so v1.0.2 and v1.0.3 of the same package compare as one target."""
    return re.sub(r"@[^@/]+$", "", name)


def prior_vuln_classes(db: DB, target_name: str) -> tuple[set[str], str | None]:
    """The VULNERABLE finding-classes from the most recent prior scan of this base package.
    Returns (classes, the matched prior target name) — ([], None) if never scanned before.
    `target_name` may be a full launch command; it is reduced to the package name first."""
    base = _base(_target_name(target_name))
    rows = db.conn.execute(
        "SELECT t.id tid, t.name n, MAX(s.scanned_at) last FROM targets t "
        "JOIN scans s ON s.target_id=t.id WHERE s.verdict='VULNERABLE' GROUP BY t.id").fetchall()
    cand = [r for r in rows if _base(r["n"]) == base]
    if not cand:
        return set(), None
    latest = max(cand, key=lambda r: r["last"])
    cls = db.conn.execute("SELECT mode FROM scans WHERE target_id=? AND verdict='VULNERABLE'",
                          (latest["tid"],)).fetchall()
    return {c["mode"].split(":")[-1] for c in cls}, latest["n"]


def classify(prior: set[str], current: set[str]) -> dict:
    """Pure delta: what a re-test resolved, newly introduced, or left unchanged."""
    return {"resolved": sorted(prior - current),
            "new": sorted(current - prior),
            "unchanged": sorted(prior & current)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt diff", description="re-test a target and diff vs its last findings")
    p.add_argument("--target-stdio", required=True, metavar="CMD")
    args = p.parse_args(argv)

    db = DB()
    prior, prior_name = prior_vuln_classes(db, args.target_stdio)
    db.close()
    try:
        rep = asyncio.run(run_full_scan(shlex.split(args.target_stdio)))
    except ScanError as e:
        print(f"INCONCLUSIVE — could not probe target: {e}", file=sys.stderr)
        return 2
    current = {f["cls"] for f in rep["findings"]}

    if prior_name is None:
        print(f"re-test: {args.target_stdio}\n  no prior findings on record — baseline is "
              f"{'VULNERABLE: ' + ', '.join(sorted(current)) if current else 'CLEAN'}.")
        return 1 if current else 0

    d = classify(prior, current)
    print(f"re-test: {args.target_stdio}\n  compared against prior scan of `{prior_name}`")
    print(f"  ✅ RESOLVED ({len(d['resolved'])}): {', '.join(d['resolved']) or '—'}")
    print(f"  🔴 NEW ({len(d['new'])}):      {', '.join(d['new']) or '—'}")
    print(f"  ⚠️  UNCHANGED ({len(d['unchanged'])}): {', '.join(d['unchanged']) or '—'}")
    return 1 if (d["new"] or d["unchanged"]) else 0


if __name__ == "__main__":
    sys.exit(main())
