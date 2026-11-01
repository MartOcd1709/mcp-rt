"""CLI: `python -m mcp_rt.agent_tier <roe.json>` (also wired as `mcp-rt assess`).

Offline by default (DeterministicPlanner, no model, no network). Live is gated: --live requires an RoE whose
mode is "live" with live_approved_by/at set (U4 supplies the live planner; without it --live still refuses).
Prints the four honest sections: PROVEN, LEADS, CLEARED, INCONCLUSIVE, plus coverage and the stop reason.
"""
import argparse
import json
import sys

from mcp_rt.agent_tier.roe import RoEError
from mcp_rt.agent_tier.run import assess


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-rt assess",
                                 description="Bounded, oracle-gated MCP assessment agent (sealed, offline).")
    ap.add_argument("roe", help="path to the signed roe.json (scope, surface, classes, budget, expiry)")
    ap.add_argument("--live", action="store_true", help="opt in to live mode (requires an approved live RoE)")
    ap.add_argument("--json", action="store_true", help="print the full machine-readable report")
    args = ap.parse_args(argv)
    try:
        rep = assess(args.roe, allow_live=args.live)
    except RoEError as exc:
        print(f"RoE refused: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(rep, indent=2, default=str))
        return 0
    c = rep["coverage"]
    print(f"stop: {rep['stop_reason']}  ·  objectives {c['objectives']} · actions {c['actions_used']} · "
          f"proven {c['flagged']} · leads {c['leads']} · cleared {c['cleared']} · inconclusive {c['inconclusive']}")
    if rep["integrity_note"]:
        print(f"  ! integrity: {rep['integrity_note']}")
    for bucket, tag in (("proven", "PROVEN"), ("leads", "LEAD"), ("cleared", "CLEAR"), ("inconclusive", "INCONCL")):
        for r in rep[bucket]:
            print(f"  [{tag:7}] {r['class']:18} {r['tool']:18} {r['method']:22} {r['evidence'][:70]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
