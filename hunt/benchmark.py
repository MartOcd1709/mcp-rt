"""MCP Security Benchmark — a comparable, citable grade for any MCP server.

Wraps the unified scan (hunt.report.run_full_scan) in a versioned scoring model so a server's
security posture becomes one number + one letter grade + an OWASP MCP Top 10 scorecard — the
reference result the ecosystem can measure against (the "open benchmark" pillar).

Spec: docs/MCP_SECURITY_BENCHMARK.md. Ground-truth only (honeytoken / sentinel / canary); the
score reflects the controls actively tested, and coverage is always stated honestly.

    python -m hunt.benchmark --target-stdio "npx some-mcp-server"
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import sys
from pathlib import Path

from hunt.report import OWASP_MCP_TOP10, TESTED_CONTROLS, run_full_scan

BENCHMARK_VERSION = "1.0"
_SEV_WEIGHT = {"Critical": 40, "High": 25, "Medium": 10, "Low": 3}
_GRADE_BANDS = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]


def _grade(score: int) -> str:
    return next(g for cut, g in _GRADE_BANDS if score >= cut)


def grade_report(rep: dict) -> dict:
    """Turn a scan report into a benchmark result: score, grade, OWASP scorecard, coverage."""
    deduction = sum(_SEV_WEIGHT.get(f["sev"], 10) for f in rep["findings"])
    score = max(0, 100 - deduction)
    tested = [c for c in rep["compliance"] if c["status"] != "NOT TESTED"]
    passed = [c for c in tested if c["status"] == "PASS"]
    return {
        "benchmark": "MCP Security Benchmark",
        "version": BENCHMARK_VERSION,
        "target": rep["target"],
        "scanned_at": rep["scanned_at"],
        "score": score,
        "grade": _grade(score),
        "controls_tested": len(tested),
        "controls_total": len(OWASP_MCP_TOP10),
        "controls_passed": len(passed),
        "coverage": f"{len(TESTED_CONTROLS)}/{len(OWASP_MCP_TOP10)} OWASP MCP Top 10 controls actively tested",
        "findings_by_severity": rep["counts"],
        "scorecard": rep["compliance"],
        "badge": (f"MCP-SEC Benchmark v{BENCHMARK_VERSION} — Grade {_grade(score)} "
                  f"({score}/100) — {len(passed)}/{len(tested)} tested controls pass"),
    }


async def run_benchmark(argv: list[str]) -> dict:
    rep = await run_full_scan(argv)
    result = grade_report(rep)
    result["_findings"] = rep["findings"]
    return result


def render_scorecard(b: dict) -> str:
    L = [f"# MCP Security Benchmark v{b['version']} — Scorecard", "",
         f"**Target:** `{b['target']}`  ", f"**Date:** {b['scanned_at']}", "",
         f"## Grade: {b['grade']}  ·  Score: {b['score']}/100", "",
         f"- **OWASP controls passed:** {b['controls_passed']} / {b['controls_tested']} tested",
         f"- **Coverage:** {b['coverage']}",
         f"- **Findings:** " + (", ".join(f"{n} {s}" for s, n in b["findings_by_severity"].items())
                                 or "none"), "",
         "## OWASP MCP Top 10 scorecard", "", "| Control | Result |", "|---|---|"]
    for c in b["scorecard"]:
        mark = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NOT TESTED": "— not tested"}[c["status"]]
        L.append(f"| {c['id']} {c['title']} | {mark} |")
    L += ["", f"> `{b['badge']}`", "",
          "> Ground-truth methodology (planted honeytoken / sentinel / canary), not heuristic. "
          "Score reflects the actively-tested controls; see docs/MCP_SECURITY_BENCHMARK.md.", ""]
    return "\n".join(L)


def preserve(b: dict) -> str:
    base = Path(__file__).resolve().parent / "benchmark_results"
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in b["target"])[:50] or "target"
    d = base / f"{stamp}_{safe}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "scorecard.md").write_text(render_scorecard(b))
    (d / "scorecard.json").write_text(json.dumps(b, indent=2, default=str))
    return str(d)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hunt.benchmark", description="MCP Security Benchmark")
    p.add_argument("--target-stdio", required=True, metavar="CMD")
    args = p.parse_args(argv)
    import shlex
    b = asyncio.run(run_benchmark(shlex.split(args.target_stdio)))
    out = preserve(b)
    print(render_scorecard(b))
    print(f"[scorecard preserved: {out}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
