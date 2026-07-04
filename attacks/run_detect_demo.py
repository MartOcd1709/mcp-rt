"""Detection demo — runs the runtime taint monitor over the CC-Hunt artifacts.

This is the defensive counterpart to attacks/run_cc_hunt.py.  It loads the captured
CC-Hunt report(s), runs mcp_rt.detect.analyze_session over each of the four records, and
prints a verdict table:

  MCP-25 workflow_scaffold_exfil  => DETECTED  (source tool, sink tool, tainted marker,
                                                undeclared host, rationale)
  MCP-22/23/24                    => CLEAR

The detector never reads the harness's detail.exfil boolean; it independently recovers the
planted honeytoken marker, reconstructs the tool-call and egress taps, and correlates a
credential source read with an undeclared-host egress.  detail.exfil is used only here, as
a self-test oracle: if any detector verdict disagrees with it, the script exits non-zero.

Usage:
  .venv/bin/python attacks/run_detect_demo.py
  .venv/bin/python attacks/run_detect_demo.py --report report_cc_hunt.json \\
      --also evidence/report_cc_hunt_run1_20260703_121620.json
"""
import argparse
import json
import sys
from pathlib import Path

from mcp_rt.detect import analyze_session, recover_planted_marker, trace_from_report_record

_DEFAULT_REPORT = "report_cc_hunt.json"
_DEFAULT_ALSO = "evidence/report_cc_hunt_run1_20260703_121620.json"


def _load(path: str) -> list:
    return json.loads(Path(path).read_text())


def _analyse(record: dict):
    marker = recover_planted_marker(record)
    trace = trace_from_report_record(record, marker=marker)
    return analyze_session(trace), marker


def _run_report(path: str, label: str) -> bool:
    """Analyse every record in one report; return True if all verdicts match the oracle."""
    records = _load(path)
    print("=" * 78)
    print(f"  {label}: {path}")
    print("=" * 78)

    ok = True
    for r in records:
        result, marker = _analyse(r)
        oracle = bool(r.get("detail", {}).get("exfil"))  # self-test only, not detector input
        verdict = "DETECTED" if result.flagged else "CLEAR"
        agree = result.flagged == oracle
        ok = ok and agree
        flag = "ok" if agree else "MISMATCH"

        print(f"\n  {r['mcp38']}")
        print(f"    attack        : {r['attack']}")
        print(f"    verdict       : {verdict:<9} (oracle detail.exfil={oracle})  [{flag}]")
        if result.flagged:
            print(f"    source tool   : {result.source}")
            print(f"    sink tool     : {result.sink}")
            print(f"    tainted value : {result.tainted_value}")
            print(f"    undeclared host: {result.undeclared_host}")
        print(f"    rationale     : {result.rationale}")
    print()
    return ok


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="mcp-rt detection demo — runtime taint monitor vs the CC-Hunt artifacts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--report", default=_DEFAULT_REPORT,
                   help=f"Primary report JSON (default: {_DEFAULT_REPORT})")
    p.add_argument("--also", default=_DEFAULT_ALSO,
                   help=f"Additional report to cross-check (default: {_DEFAULT_ALSO}); "
                        "pass '' to skip")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    reports = [(args.report, "Run 2 (current)")]
    if args.also:
        reports.append((args.also, "Run 1 (backup)"))

    all_ok = True
    for path, label in reports:
        if not Path(path).exists():
            print(f"[skip] {label}: {path} not found", file=sys.stderr)
            continue
        all_ok = _run_report(path, label) and all_ok

    print("=" * 78)
    if all_ok:
        print("  SELF-TEST PASSED — every detector verdict matches the detail.exfil oracle.")
        print("=" * 78)
        sys.exit(0)
    print("  SELF-TEST FAILED — a detector verdict disagreed with the oracle.")
    print("=" * 78)
    sys.exit(1)


if __name__ == "__main__":
    main()
