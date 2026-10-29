"""python -m mcp_rt.bench run [--clients NAMES] [--trials K] [--fixtures DIR] [--out DIR] [--db PATH]

Offline mock clients only. Any other client name is refused: live real-agent runs are disabled until Ved authorizes
them (Phase B design, Q5), and a live run would also need the model-routing check to be reported first.
"""
import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path

from . import detector, detector_report, engine, report, score
from .corpus import discover
from .db import BenchDB
from .mocks import MOCK_CLIENTS

REPO = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURES = REPO / "fixtures"
DEFAULT_RESULTS = REPO / "bench_results"


def _git_sha() -> str:
    proc = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO, capture_output=True, text=True)
    return proc.stdout.strip() or "unknown"


def _detect(args) -> int:
    """Scorecard B: mcp-rt's own deterministic detector over the corpus, plus the calibration fixtures."""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{_git_sha()}-B"
    out_dir = args.out or (DEFAULT_RESULTS / run_id)

    rows = []
    for fixture in discover(args.fixtures):
        features = fixture.label.get("protocol_features", [])
        server = fixture.path / "server.py"
        rows.append({"name": fixture.name, "role": fixture.kind, "subtlety": fixture.label.get("subtlety", "?"),
                     "cousin": fixture.label.get("cousin", "?"), "features": features,
                     "reasons": detector.gap_reasons(features) if fixture.kind == "attack" else [],
                     "path": str(server), "manifest": fixture.manifest(), **detector.scan_target(server)})
    for name, expect in detector.CALIBRATION:
        server = detector.CALIBRATION_DIR / f"{name}.py"
        rows.append({"name": name, "role": "calibration", "expect": expect, "features": [], "reasons": [],
                     "path": str(server), "manifest": {"server_sha256": detector.sha256_of(server)},
                     **detector.scan_target(server)})

    db = BenchDB(args.db)
    for row in rows:
        db.record(run_id, {
            "fixture": row["name"], "kind": "detector", "client": "mcp-rt run_full_scan", "trial": 1,
            "verdict": row["verdict"], "token_hit": False, "lure_taken": False, "canary_paths": [],
            "error": row["error"],
            "transcript": [json.dumps({"role": row["role"], "findings": row["findings"], "leads": row["leads"],
                                       "coverage": row["coverage"], "reasons": row["reasons"]})],
            "started_at": stamp, "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        })
    db.close()

    scores = detector.score(rows)
    meta = {
        "run_id": run_id,
        "git_sha": _git_sha(),
        "entrypoint": detector.ENTRYPOINT,
        "excluded": list(detector.EXCLUDED),
        "taint_monitor": detector.TAINT_NOTE,
        "flag": "primary = confirmed finding (VULNERABLE); leads (SUSPECTED) reported separately; MCP06 is not a flag",
        "isolation": "fixtures and probe targets: stdio subprocesses; detector offline; no model, no network",
        "calibration": [{"name": n, "expect": e, "sha256": detector.sha256_of(detector.CALIBRATION_DIR / f"{n}.py")}
                        for n, e in detector.CALIBRATION],
    }
    detector_report.write(out_dir, meta, scores, rows)

    print(f"detector recall:   confirmed {scores['recall_confirmed']} | including leads {scores['recall_any']}")
    print(f"controls cleared:  {scores['specificity_confirmed']} | precision {scores['precision_confirmed']}")
    calibration_summary = ", ".join(f"{c['name']}={c['result']}" for c in scores["calibration"])
    print(f"calibration:       {'PASS' if scores['calibration_passed'] else 'FAIL'} ({calibration_summary})")
    print(f"scorecard: {out_dir / 'scorecard_B.md'}")
    print(f"results:   {out_dir / 'results_B.json'}")
    print(f"ledger:    {args.db} (run {run_id}, kind='detector')")
    return 0 if scores["calibration_passed"] else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mcp_rt.bench", description="Phase B scorecards A and B (offline)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the susceptibility scorecard against the fixture corpus")
    run.add_argument("--clients", default=",".join(MOCK_CLIENTS), help="comma-separated offline client names")
    run.add_argument("--trials", type=int, default=3, help="trials per (fixture, client) cell")
    run.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    run.add_argument("--out", type=Path, default=None, help="output directory (default bench_results/<run_id>)")
    run.add_argument("--db", type=Path, default=DEFAULT_RESULTS / "bench.db")
    det = sub.add_parser("detect", help="score mcp-rt's deterministic detector (scorecard B, offline)")
    det.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    det.add_argument("--out", type=Path, default=None, help="output directory (default bench_results/<run_id>-B)")
    det.add_argument("--db", type=Path, default=DEFAULT_RESULTS / "bench.db")
    args = parser.parse_args(argv)
    if args.cmd == "detect":
        return _detect(args)

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
