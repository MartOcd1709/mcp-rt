"""Continuous monitoring + alerting (B1) — re-scan tracked targets and raise an ALERT on any NEW
finding vs the last recorded scan. The automation a manual consultancy structurally cannot offer:
"they test once; we test every version, every day." Cron it:

    0 */6 * * *  cd ~/Desktop/mcp-rt && mcp-rt monitor --from-ledger 40

Targets are re-pinned to @latest so a monitor run tests the CURRENT published build — the point is to
catch a regression or a newly-introduced bug the day it ships. Alerts append to hunt/alerts.jsonl.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import re
import shlex
import sys
from pathlib import Path

from hunt.diff import classify, prior_vuln_classes
from hunt.findings_db import DB
from hunt.report import preserve, record, run_full_scan

ALERTS = Path(__file__).resolve().parent / "alerts.jsonl"


def _relatest(cmd: str) -> str:
    """Re-pin an exact trailing version (`pkg@1.2.3`) to `@latest` so we test the current build.
    Leaves a scoped name's `@scope/` and an unversioned package untouched."""
    return re.sub(r"@[^@/\s]+(?=\s|$)", "@latest", cmd)


def to_alert(target: str, prior: set, current: set, when: str) -> dict | None:
    """An alert iff a re-test introduced a NEW finding-class. Pure + testable."""
    d = classify(prior, current)
    if not d["new"]:
        return None
    return {"target": target, "when": when, "new": d["new"],
            "resolved": d["resolved"], "unchanged": d["unchanged"]}


def monitor(targets: list[str], timeout: int = 120) -> list[dict]:
    db = DB()
    when = datetime.datetime.now().isoformat(timespec="seconds")
    alerts = []
    for raw in targets:
        cmd = _relatest(raw)
        prior, _ = prior_vuln_classes(db, cmd)
        try:
            rep = asyncio.run(asyncio.wait_for(run_full_scan(shlex.split(cmd)), timeout=timeout))
        except Exception as e:  # noqa: BLE001
            print(f"  {cmd}: inconclusive ({type(e).__name__})")
            continue
        current = {f["cls"] for f in rep["findings"]}
        record(rep, preserve(rep))                                    # update the baseline
        a = to_alert(cmd, prior, current, when)
        status = "CLEAN" if not current else "VULNERABLE: " + ", ".join(sorted(current))
        print(f"  {cmd}: {status}" + (f"   🔴 NEW: {', '.join(a['new'])}" if a else ""))
        if a:
            alerts.append(a)
    db.close()
    if alerts:
        with open(ALERTS, "a") as f:
            for a in alerts:
                f.write(json.dumps(a) + "\n")
        print(f"\n⚠️  {len(alerts)} alert(s) written to {ALERTS}")
    return alerts


def _ledger_targets(db: DB, limit: int) -> list[str]:
    """Most-recently-added targets' launch commands (relaunchable npx/uvx ones), for --from-ledger."""
    rows = db.conn.execute(
        "SELECT install_cmd FROM targets WHERE install_cmd LIKE 'npx %' OR install_cmd LIKE 'uvx %' "
        "ORDER BY added_at DESC LIMIT ?", (limit,)).fetchall()
    return [r["install_cmd"] for r in rows]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt monitor", description="continuous re-scan + alert on new findings")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--targets", nargs="+", metavar="CMD", help="explicit launch commands to monitor")
    g.add_argument("--from-ledger", type=int, metavar="N", help="monitor the N most-recent ledger targets")
    p.add_argument("--timeout", type=int, default=120)
    args = p.parse_args(argv)

    if args.from_ledger:
        db = DB()
        targets = _ledger_targets(db, args.from_ledger)
        db.close()
    else:
        targets = args.targets
    print(f"monitor: re-testing {len(targets)} target(s) at latest version\n")
    alerts = monitor(targets, timeout=args.timeout)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
