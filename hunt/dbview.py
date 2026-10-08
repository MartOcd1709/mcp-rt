"""`mcp-rt db` — look at the findings database without writing SQL.

    mcp-rt db                 # overview: every table, its row count and fields, plus the headline summary
    mcp-rt db <table>         # recent rows of one table, aligned (default 20)
    mcp-rt db <table> -n 50   # more rows

Read-only. The point is to check state fast; for ad-hoc queries use sqlite3 or sqlitebrowser.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .findings_db import DB, DB_PATH


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


def _tables(c):
    return [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]


def _print_table(rows, cols):
    """Aligned column print, values truncated so the terminal never floods."""
    if not rows:
        print("  (no rows)")
        return
    data = [[(str(r[c]) if r[c] is not None else "") for c in cols] for r in rows]
    widths = [min(max(len(c), *(len(d[i]) for d in data)), 40) for i, c in enumerate(cols)]
    line = "  " + "  ".join(c[:w].ljust(w) for c, w in zip(cols, widths))
    print(line)
    print("  " + "  ".join("-" * w for w in widths))
    for d in data:
        print("  " + "  ".join(v[:w].ljust(w) for v, w in zip(d, widths)))


def overview(path=DB_PATH) -> int:
    c = _conn(path)
    print(f"database: {path}\n")
    for t in _tables(c):
        n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        fields = ", ".join(r["name"] for r in c.execute(f"PRAGMA table_info({t})"))
        mark = "  ●" if n else "   "
        print(f"{mark} {t:<16} {n:>5} rows   {fields}")
    # headline summary (reuses the ledger's own numbers)
    try:
        s = DB(path).summary()
        print(f"\nsummary: {s['targets_tested']} servers · {s['by_verdict']} · "
              f"open hypotheses {s.get('open_hypotheses', 0)}")
    except Exception:  # noqa: BLE001 — summary is a nicety, never fail the view
        pass
    return 0


def show(table: str, limit: int, path=DB_PATH) -> int:
    c = _conn(path)
    if table not in _tables(c):
        print(f"no such table: {table}\ntables: {', '.join(_tables(c))}")
        return 2
    cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]
    order = " ORDER BY id DESC" if "id" in cols else ""
    rows = c.execute(f"SELECT * FROM {table}{order} LIMIT ?", (limit,)).fetchall()
    print(f"{table} — {len(rows)} most-recent row(s):\n")
    _print_table(rows, cols)
    return 0


_CLASS_ALIAS = {"path_confinement_bypass": "path_traversal"}


def _class_of(mode: str):
    """The attack class a historical scan row belongs to, from its `mode` (e.g. 'report:ssrf')."""
    if mode and ":" in mode:
        c = mode.split(":", 1)[1]
        return _CLASS_ALIAS.get(c, c)
    return None


def backfill(path=DB_PATH) -> int:
    """Migrate existing `scans` rows into the relationship backbone: one `findings` row per scan, plus a
    knowledge-graph `attack_patterns` node per confirmed one. Idempotent (skips scans already backfilled)."""
    import re
    from .report import CLASS_META
    db = DB(path)
    db.seed_classes()
    done = {r["scan_id"] for r in
            db.conn.execute("SELECT DISTINCT scan_id FROM findings WHERE scan_id IS NOT NULL")}
    n = p = 0
    for s in db.conn.execute("SELECT id,target_id,mode,verdict,marker,notes FROM scans").fetchall():
        if s["id"] in done:
            continue
        cls = _class_of(s["mode"])
        cls = cls if cls in CLASS_META else ""          # unknown/classless -> NULL class, still a finding
        notes = s["notes"] or ""
        m = re.search(r"\bon ([\w./@-]+)", notes)
        tool = m.group(1).rstrip(":") if m else ""
        fid = db.add_finding(s["target_id"], scan_id=s["id"], class_id=cls, tool=tool,
                             severity=CLASS_META.get(cls, {}).get("sev", ""), marker=s["marker"] or "",
                             evidence=notes[:500], rationale=notes[:200], verdict=s["verdict"])
        n += 1
        if s["verdict"] == "VULNERABLE" and cls:
            db.add_attack_pattern(class_id=cls, finding_id=fid, technique=notes[:200],
                                  outcome="confirmed (backfilled)", cwe=CLASS_META[cls].get("cwe", ""))
            p += 1
    db.close()
    print(f"backfilled {n} finding(s) and {p} knowledge-graph node(s) from the existing scans.")
    return 0


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="mcp-rt db", description="inspect the findings database (no SQL)")
    p.add_argument("table", nargs="?", help="a table name to list rows from; omit for the overview")
    p.add_argument("-n", "--limit", type=int, default=20, help="rows to show (default 20)")
    p.add_argument("--backfill", action="store_true",
                   help="populate findings + attack_patterns from existing scans (idempotent)")
    args = p.parse_args(argv)
    if args.backfill:
        return backfill()
    return show(args.table, args.limit) if args.table else overview()


def _selftest():
    import tempfile
    p = Path(tempfile.mkdtemp()) / "v.db"
    db = DB(p)
    db.add_target(name="demo-mcp", install_cmd="npx -y demo-mcp")
    db.close()
    assert overview(p) == 0 and show("targets", 10, p) == 0 and show("nope", 10, p) == 2
    print("dbview selftest OK")


if __name__ == "__main__":
    import sys
    _selftest() if "--selftest" in sys.argv else sys.exit(main())
