"""CLI.

    python -m mcp_rt.runtime run [--hints FILE] -- <server argv ...>   one server, JSON record on stdout
    python -m mcp_rt.runtime corpus   lab targets without and with operator inputs; results and scorecard under bench_results/
"""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from mcp_rt.runtime.runner import LIMITS, load_hints, run_server

REPO = Path(__file__).resolve().parents[2]
CONTROL_GATES = json.loads(Path(__file__).with_name("gates.json").read_text())["control_gates"]


def corpus_targets():
    attacks = sorted((REPO / "fixtures").glob("*/server.py"))
    controls = sorted((REPO / "fixtures" / "_controls").glob("*/server.py"))
    return ([(p.parent.name, "attack", [sys.executable, str(p.resolve())]) for p in attacks]
            + [(p.parent.name, "control", [sys.executable, str(p.resolve())]) for p in controls])


def effective(row):
    """The matrix gate reads the run with operator inputs where one exists, otherwise the run without."""
    return row["hinted"] or row["generic"]


def _counts(records):
    return ", ".join(f"{verdict} {n}" for verdict, n in sorted(Counter(r["verdict"] for r in records).items())) or "none"


def write_scorecard(rows, out_dir, stamp):
    attacks = [r for r in rows if r["role"] == "attack"]
    by_name = {r["name"]: r for r in rows}
    lines = [f"# Unit 3 runtime observation: lab corpus ({stamp})", "",
             "Sealed namespace, no internet, no model. Only this run's own test value counts as proof.", "",
             "Two modes. **Without operator input** is the default: a router whose downstream tool the harness cannot",
             "name is INCONCLUSIVE (`sandbox_not_exercised`), never CLEAN. **With operator input** (`hints.json`, data),",
             "the same server is driven to its sink. The matrix gate reads the operator-input run where one exists.", "",
             "| role | target | without operator input | with operator input | evidence (gate run) |",
             "|---|---|---|---|---|"]
    for r in rows:
        operator = f"**{r['hinted']['verdict']}** `{r['hinted']['method']}`" if r["hinted"] else "-"
        lines.append(f"| {r['role']} | `{r['name']}` | **{r['generic']['verdict']}** `{r['generic']['method']}` | "
                     f"{operator} | {effective(r)['evidence']} |")
    lines += ["", f"**Lab attacks without operator input:** {_counts([r['generic'] for r in attacks])} "
              f"(of {len(attacks)}).",
              f"**Lab attacks, gate run:** {_counts([effective(r) for r in attacks])} (of {len(attacks)}).", "",
              "**Matrix gate:**"]
    hits = sum(effective(r)["verdict"] == "VULNERABLE" for r in attacks)
    lines.append(f"- attacks VULNERABLE: {hits}/{len(attacks)} -> {'PASS' if hits == len(attacks) else 'NOT MET'}")
    for name in CONTROL_GATES:
        verdict = effective(by_name[name])["verdict"] if name in by_name else "MISSING"
        lines.append(f"- `{name}` CLEAN: {verdict} -> {'PASS' if verdict == 'CLEAN' else 'NOT MET'}")
    lines += ["", "**Limits, stated in every record:**"] + [f"- {item}" for item in LIMITS]
    path = out_dir / "scorecard.md"
    path.write_text("\n".join(lines) + "\n")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m mcp_rt.runtime")
    sub = ap.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("run")
    one.add_argument("--hints", help="JSON file: tool name -> {argument: value}; a value may carry {token}")
    one.add_argument("server", nargs="+")
    sub.add_parser("corpus")
    args = ap.parse_args(argv)

    if args.cmd == "run":
        hints = json.loads(Path(args.hints).read_text()) if args.hints else None
        server = [part for part in args.server if part != "--"]
        print(json.dumps(run_server(server, hints=hints), indent=2, default=str))
        return 0

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_dir = REPO / "bench_results" / f"runtime-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    operator_inputs = load_hints()
    rows = []
    for name, role, argv_ in corpus_targets():
        generic = run_server(argv_)
        hinted = run_server(argv_, hints=operator_inputs[name]) if name in operator_inputs else None
        rows.append({"name": name, "role": role, "generic": generic, "hinted": hinted})
        operator = f"{hinted['verdict']} {hinted['method']}" if hinted else "-"
        print(f"{role:8} {name:28} no-input {generic['verdict']:12} {generic['method']:22} | operator {operator}",
              flush=True)
    (out_dir / "results.json").write_text(json.dumps(rows, indent=2, default=str))
    card = write_scorecard(rows, out_dir, stamp)
    attacks = [r for r in rows if r["role"] == "attack"]
    controls = [r for r in rows if r["role"] == "control"]
    print(f"\nattacks, without operator input: {_counts([r['generic'] for r in attacks])}")
    print(f"attacks, gate run:               {_counts([effective(r) for r in attacks])}")
    print(f"controls, gate run:              {_counts([effective(r) for r in controls])}")
    print(f"scorecard: {card}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
