"""python -m mcp_rt.bench run [--clients NAMES] [--trials K] [--fixtures DIR] [--out DIR] [--db PATH]

Offline mock clients only. Any other client name is refused: live real-agent runs are disabled until Ved authorizes
them (Phase B design, Q5), and a live run would also need the model-routing check to be reported first.
"""
import argparse
import datetime
import subprocess
import sys
from pathlib import Path

from . import engine, report, score
from .corpus import discover
from .db import BenchDB
from .mocks import MOCK_CLIENTS

REPO = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURES = REPO / "fixtures"
DEFAULT_RESULTS = REPO / "bench_results"


def _git_sha() -> str:
    proc = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO, capture_output=True, text=True)
    return proc.stdout.strip() or "unknown"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mcp_rt.bench", description="Phase B scorecard A (mock clients)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the susceptibility scorecard against the fixture corpus")
    run.add_argument("--clients", default=",".join(MOCK_CLIENTS), help="comma-separated offline client names")
    run.add_argument("--trials", type=int, default=3, help="trials per (fixture, client) cell")
    run.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    run.add_argument("--out", type=Path, default=None, help="output directory (default bench_results/<run_id>)")
    run.add_argument("--db", type=Path, default=DEFAULT_RESULTS / "bench.db")
    args = parser.parse_args(argv)

    requested = [c.strip() for c in args.clients.split(",") if c.strip()]
    refused = [c for c in requested if c not in MOCK_CLIENTS]
    if refused:
        print(f"refused: {refused}. Live real-agent runs are disabled until Ved authorizes them (Phase B design Q5). "
              f"Offline clients: {sorted(MOCK_CLIENTS)}", file=sys.stderr)
        return 2
    if args.trials < 1:
        print("--trials must be at least 1", file=sys.stderr)
        return 2

    fixtures = discover(args.fixtures)
    clients = [MOCK_CLIENTS[name]() for name in requested]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{_git_sha()}"
    out_dir = args.out or (DEFAULT_RESULTS / run_id)

    rows = engine.run_matrix(fixtures, clients, args.trials)
    db = BenchDB(args.db)
    for row in rows:
        db.record(run_id, row)
    db.close()

    scores = score.score(rows)
    meta = {
        "run_id": run_id,
        "git_sha": _git_sha(),
        "trials": args.trials,
        "clients": requested,
        "fixtures": [{"name": f.name, "kind": f.kind, **f.manifest(), "label": f.label} for f in fixtures],
        "isolation": "fixtures: stdio subprocess + loopback canary; clients: in-process scripted mocks",
        "live_runs": "disabled",
    }
    report.write(out_dir, meta, scores, rows, [{"name": f.name, "kind": f.kind, "label": f.label} for f in fixtures])

    for cl in requested:
        a, f = scores["agent_susceptibility"][cl], scores["control_false_alarms"][cl]
        print(f"{cl}: ASR cells {a['cells']} (trials {a['trials']}) | control false alarms {f['cells']} (trials {f['trials']})")
    print(f"scorecard: {out_dir / 'scorecard.md'}")
    print(f"results:   {out_dir / 'results.json'}")
    print(f"ledger:    {args.db} (run {run_id})")
    return 0
