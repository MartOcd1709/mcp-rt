"""Daily discovery + enrich run — the data-collection cadence behind the enriched platform.

Each run scans three lanes (deduped against the ledger):
  1. CURATED — a set of TOP / standard MCP servers (the ones real stacks embed), the credibility
     anchor: "we test the servers big orgs actually use";
  2. POPULAR — the most-DOWNLOADED (high-usage) discovered servers, where a credibility-grade
     finding would land;
  3. FRESH — long-tail maintained servers not already in the ledger (where our past GHSAs came from).

Everything is installed and run LOCALLY from its published package (never a hosted instance), so
no third party is touched; results + full per-server reports + a dated run log are preserved and
every scan is recorded to findings.db. Idempotent: a server scanned within --retest-days is
skipped, so the honest denominator grows with NEW servers instead of repeating the same ones.

    python -m hunt.daily                  # curated + 5 popular + up to 15 fresh
    python -m hunt.daily --popular 10     # scan more high-usage servers
    python -m hunt.daily --cap 25         # scan more long-tail servers
    python -m hunt.daily --top-only       # only the curated anchors (no discovery)
    python -m hunt.daily --no-top         # discovery only (popular + fresh)
    python -m hunt.daily --plan           # print what WOULD be scanned (after dedup), install nothing

Cron it (daily 9am):   0 9 * * *  cd ~/Desktop/mcp-rt && python -m hunt.daily --cap 20
Guardrail: local, open-source servers only; synthetic probes; responsible disclosure before any
public listing (see the mcp-hunt skill).
"""
from __future__ import annotations

import argparse
import datetime
import sys
from collections import Counter
from pathlib import Path

from hunt.findings_db import DB
from hunt.sweep import _QUERIES, _cmd_for, discover, discover_pypi, scan_one

# Curated standard/high-trust MCP servers big orgs embed. Edit freely — any name that is not a
# real npm package simply records INCONCLUSIVE [INSTALL_FAILED], which is honest, not a crash.
TOP_SERVERS = [
    "@modelcontextprotocol/server-filesystem",          # the canonical reference FS server
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything",          # exercises every MCP feature
    "@modelcontextprotocol/server-sequential-thinking",
    "@upstash/context7-mcp",                            # widely embedded docs server
    "firecrawl-mcp",                                    # popular web-scrape server
    "@playwright/mcp",                                  # browser-automation server
]

RUNS_DIR = Path(__file__).resolve().parent / "runs"


def _plan(do_top: bool, top_only: bool, cap: int, retest_days: float,
          popular_cap: int = 5, pypi_cap: int = 10) -> tuple[list, list, list, list]:
    """Resolve the four target lanes after dedup, installing nothing:
      curated (TOP_SERVERS) · popular (most-downloaded npm) · fresh (npm long tail) · pypi (Python/uvx).
    retest_days <= 0 means always re-test (dedup nothing); > 0 skips servers tested within the window."""
    db = DB()
    seen = set() if retest_days <= 0 else db.tested_names(within_days=retest_days)
    db.close()
    top = ([{"name": n, "cmd": _cmd_for(n)} for n in TOP_SERVERS if n not in seen]
           if do_top else [])
    if top_only:
        return top, [], [], []
    popular = [t for t in discover(_QUERIES, popular_cap, max_downloads=10_000_000,
                                   min_downloads=2000, maintained=True, popular=True)
               if t["name"] not in seen][:popular_cap]
    pop_names = {t["name"] for t in popular}
    fresh = [t for t in discover(_QUERIES, cap, max_downloads=2000, min_downloads=10, maintained=True)
             if t["name"] not in seen and t["name"] not in pop_names][:cap]
    pypi = discover_pypi(pypi_cap, seen) if pypi_cap > 0 else []   # Python ecosystem (uvx)
    return top, popular, fresh, pypi


def _write_run_log(date: str, results: list[dict], incat: Counter, classes: Counter) -> str:
    RUNS_DIR.mkdir(exist_ok=True)
    tested = [r for r in results if r["verdict"] != "INCONCLUSIVE"]
    vuln = [r for r in tested if r["verdict"] == "VULNERABLE"]
    L = [f"# Daily MCP enrich run — {date}", "",
         f"- scanned: **{len(tested)}** · inconclusive: **{len(results) - len(tested)}** · "
         f"vulnerable: **{len(vuln)}**",
         f"- inconclusive by cause: {dict(incat) or '{}'}",
         f"- findings by class: {dict(classes) or '{}'}", "",
         "| server | verdict | detail |", "|---|---|---|"]
    for r in results:
        if r["verdict"] == "INCONCLUSIVE":
            detail = f"[{r['cat']}] {r['why'][:80]}"
        elif r["findings"]:
            detail = ", ".join(f"{f['cls']}:{f['tool']}" for f in r["findings"])
        else:
            detail = f"grade {r.get('grade', '?')} ({r.get('score', '?')}/100) clean"
        L.append(f"| `{r['name']}` | {r['verdict']} | {detail} |")
    path = RUNS_DIR / f"{date}_{datetime.datetime.now():%H%M%S}.md"   # timestamped so same-day runs don't clobber
    path.write_text("\n".join(L) + "\n")
    return str(path)


def run(do_top: bool, top_only: bool, cap: int, retest_days: float, timeout: int,
        popular_cap: int = 5, pypi_cap: int = 10) -> dict:
    date = datetime.date.today().isoformat()
    top, popular, fresh, pypi = _plan(do_top, top_only, cap, retest_days, popular_cap, pypi_cap)
    targets = ([{**t, "_kind": "curated"} for t in top]
               + [{**t, "_kind": "popular"} for t in popular]
               + [{**t, "_kind": "fresh"} for t in fresh]
               + [{**t, "_kind": "pypi"} for t in pypi])
    print(f"daily enrich {date}: {len(top)} curated + {len(popular)} popular + {len(fresh)} fresh "
          f"+ {len(pypi)} pypi = {len(targets)} target(s)\n")

    if not targets:   # discovery saturated or everything deduped — clean no-op, no empty log
        print("nothing new to scan — discovery pool exhausted or all servers deduped within the "
              "retest window. Widen discovery (new queries / deeper pages / other sources) or lower "
              "--retest-days to re-scan.")
        return {"date": date, "results": [], "log": None, "ledger": DB().summary()}

    db = DB()
    results, incat, classes = [], Counter(), Counter()
    for t in targets:
        r = scan_one(t, db, timeout=timeout, source=t["_kind"])   # ledger source = lane
        results.append(r)
        if r["verdict"] == "INCONCLUSIVE":
            incat[r["cat"]] += 1
        else:
            for f in r["findings"]:
                classes[f["cls"]] += 1
    summary = db.summary()
    db.close()

    log_path = _write_run_log(date, results, incat, classes)
    print("\n=== daily summary ===")
    print(f"targets this run: {len(results)}  (inconclusive: {sum(incat.values())})")
    print(f"inconclusive by cause: {dict(incat)}")
    print(f"findings by class:     {dict(classes)}")
    print(f"ledger now: {summary}")
    print(f"run log: {log_path}")
    return {"date": date, "results": results, "log": log_path, "ledger": summary}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt daily", description="daily MCP discovery + enrich run")
    p.add_argument("--cap", type=int, default=15, help="max FRESH (long-tail) discovered servers to scan")
    p.add_argument("--popular", type=int, default=5,
                   help="max POPULAR (most-downloaded, high-usage) servers to scan (0 to skip the lane)")
    p.add_argument("--pypi", type=int, default=10,
                   help="max PYPI (Python/uvx) servers to scan (0 to skip the lane)")
    p.add_argument("--timeout", type=int, default=120, help="per-server scan timeout (s)")
    p.add_argument("--retest-days", type=float, default=30.0,
                   help="skip a server scanned within this many days (0 = always re-test)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--no-top", action="store_true", help="skip the curated top servers (discovery only)")
    g.add_argument("--top-only", action="store_true", help="scan only the curated top servers")
    p.add_argument("--plan", action="store_true", help="show what WOULD be scanned, install nothing")
    args = p.parse_args(argv)

    if args.plan:
        top, popular, fresh, pypi = _plan(not args.no_top, args.top_only, args.cap,
                                          args.retest_days, args.popular, args.pypi)
        dedup = "no dedup (always re-test)" if args.retest_days <= 0 else f"dedup within {args.retest_days}d"
        print(f"PLAN ({dedup}):")
        for lane, items in (("curated", top), ("popular", popular), ("fresh", fresh), ("pypi", pypi)):
            for t in items:
                print(f"  [{lane:7}] {t['name']}")
        print(f"\n{len(top)} curated + {len(popular)} popular + {len(fresh)} fresh + {len(pypi)} pypi = "
              f"{len(top) + len(popular) + len(fresh) + len(pypi)} target(s) — nothing installed")
        return 0
    run(not args.no_top, args.top_only, args.cap, args.retest_days, args.timeout, args.popular, args.pypi)
    return 0


if __name__ == "__main__":
    sys.exit(main())
