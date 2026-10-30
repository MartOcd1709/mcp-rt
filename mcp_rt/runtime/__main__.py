"""CLI.

    python -m mcp_rt.runtime run -- <server argv ...>   one server, JSON verdict record on stdout
    python -m mcp_rt.runtime corpus                     the lab fixtures and controls; results and scorecard under bench_results/
"""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from mcp_rt.runtime.runner import LIMITS, run_server

REPO = Path(__file__).resolve().parents[2]
CONTROL_GATES = json.loads(Path(__file__).with_name("gates.json").read_text())["control_gates"]


def corpus_targets():
    attacks = sorted((REPO / "fixtures").glob("*/server.py"))
    controls = sorted((REPO / "fixtures" / "_controls").glob("*/server.py"))
    return ([(p.parent.name, "attack", [sys.executable, str(p.resolve())]) for p in attacks]
            + [(p.parent.name, "control", [sys.executable, str(p.resolve())]) for p in controls])


def write_scorecard(rows, out_dir, stamp):
    lines = [f"# Unit 3 runtime observation: lab corpus ({stamp})", "",
             "Sealed namespace, no internet, no model. Only this run's own test value counts as proof.", "",
             "| role | target | verdict | method | evidence | calls | refused | elicitations |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['role']} | `{r['name']}` | **{r['verdict']}** | `{r['method']}` | {r['evidence']} | "
                     f"{len(r['calls'])} | {', '.join(r['refused']) or '-'} | {len(r['elicitations'])} |")
    attacks = Counter(r["verdict"] for r in rows if r["role"] == "attack")
    lines += ["", f"**Lab attacks:** VULNERABLE {attacks.get('VULNERABLE', 0)}, SUSPECTED {attacks.get('SUSPECTED', 0)}, "
              f"INCONCLUSIVE {attacks.get('INCONCLUSIVE', 0)}, CLEAN {attacks.get('CLEAN', 0)} (of {sum(attacks.values())})."]
    lines += ["", "**Control gates (the matrix):**"]
    by_name = {r["name"]: r for r in rows}
    for name in CONTROL_GATES:
        verdict = by_name.get(name, {}).get("verdict", "MISSING")
        status = "PASS" if verdict == "CLEAN" else "NOT MET"
        lines.append(f"- `{name}`: {verdict} ({status})")
    lines += ["", "**Limits, stated in every record:**"] + [f"- {item}" for item in LIMITS]
    path = out_dir / "scorecard.md"
    path.write_text("\n".join(lines) + "\n")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m mcp_rt.runtime")
    sub = ap.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("run")
    one.add_argument("server", nargs="+")
    sub.add_parser("corpus")
    args = ap.parse_args(argv)

    if args.cmd == "run":
        print(json.dumps(run_server(args.server), indent=2, default=str))
        return 0

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_dir = REPO / "bench_results" / f"runtime-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, role, argv_ in corpus_targets():
        rec = run_server(argv_)
        rec.update({"name": name, "role": role})
        rows.append(rec)
        print(f"{role:8} {name:28} {rec['verdict']:13} {rec['method']:24} {rec['evidence'][:90]}", flush=True)
    (out_dir / "results.json").write_text(json.dumps(rows, indent=2, default=str))
    card = write_scorecard(rows, out_dir, stamp)
    print(f"\nlab attacks: {dict(Counter(r['verdict'] for r in rows if r['role'] == 'attack'))}")
    print(f"controls:    {dict(Counter(r['verdict'] for r in rows if r['role'] == 'control'))}")
    print(f"scorecard: {card}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
