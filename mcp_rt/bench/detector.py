"""Scorecard B: mcp-rt's own deterministic detector, scored against the labelled corpus. Detector precision/recall.

Entrypoint: hunt.report.run_full_scan, the engine behind `mcp-rt check`. It is deterministic and offline: the impl-bug
probes, token passthrough and supply chain. Excluded: anything model-driven (the agent and hunt-agent modes, pentest,
and the credential-exfil scan, which runs a live client). The runtime taint monitor is N/A for these classes, because it
models file-read then egress (MCP-25) and no corpus class has that shape.

Flag: primary = a confirmed finding (VULNERABLE). Leads (SUSPECTED) are a separate tier, labelled. MCP06 intent-flow
exposure is an enabling-condition posture, not a finding, and is never counted as a flag.

Ground truth: attack fixtures should be flagged and controls should be cleared (each control mirrors an attack cousin).
Calibration targets are the detector's own reference fixtures: vuln_server must be flagged and safe_server cleared. If
calibration fails, the scorecard says so loudly, because the detector would then be broken and recall would mean nothing.

Never blended with scorecard A (agent susceptibility). Results go to bench.db (kind='detector') and bench_results/.
"""
import asyncio
import hashlib
import sys
from pathlib import Path

from hunt.report import run_full_scan

CALIBRATION_DIR = Path(__file__).resolve().parents[2] / "hunt" / "probe_fixtures"
CALIBRATION = (("vuln_server", "flag"), ("safe_server", "clear"))
ENTRYPOINT = "hunt.report.run_full_scan (the engine behind `mcp-rt check`): impl-bug probes + token passthrough + supply chain"
EXCLUDED = ("model-driven modes excluded: the credential-exfil scan (runs a live client), agent, hunt-agent, pentest",)
TAINT_NOTE = ("N/A: the runtime taint monitor (mcp_rt/detect) models file-read then egress (MCP-25); none of the corpus "
              "classes has that shape, so it is reported as not applicable, not as zero recall")

_OBSERVABILITY = ("the fixture forwards to MCPRT_CANARY, a channel the detector's harness does not observe "
                  "(observability gap)")
_MODEL_MISMATCH = "token passthrough tests a server's own env credential, not an agent-supplied lure (model mismatch)"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scan_target(server_py: Path) -> dict:
    """Run the detector on one fixture. An unscannable target is INCONCLUSIVE, never cleared."""
    try:
        report = asyncio.run(run_full_scan([sys.executable, str(server_py.resolve())]))
    except Exception as exc:  # noqa: BLE001 — the detector could not look, so it did not clear the target
        return {"verdict": "INCONCLUSIVE", "flagged": False, "any_flag": False, "findings": [], "leads": [],
                "coverage": {}, "error": f"{type(exc).__name__}: {exc}"[:300]}
    findings = sorted({f["cls"] for f in report["findings"]})
    leads = sorted({s["cls"] for s in report.get("suspected", [])})
    coverage: dict[str, int] = {}
    for cov in report["coverage"]:
        coverage[cov["verdict"]] = coverage.get(cov["verdict"], 0) + 1
    flagged = bool(findings)
    verdict = "VULNERABLE" if flagged else ("SUSPECTED" if leads else "CLEAN")
    return {"verdict": verdict, "flagged": flagged, "any_flag": flagged or bool(leads), "findings": findings,
            "leads": leads, "coverage": coverage, "error": None}


def gap_reasons(protocol_features) -> list[str]:
    """Why the detector cannot flag a lure class. Derived from the fixture's protocol features (data), not from names."""
    features = set(protocol_features or [])
    reasons = [_OBSERVABILITY, _MODEL_MISMATCH]
    if "elicitation" in features:
        reasons.append("the lure is an elicitation request, and no deterministic check inspects elicitation requests")
    elif "resources" in features:
        reasons.append("the lure is in resource text, and no deterministic check reads resource text for instructions")
    else:
        reasons.append("the lure sits in a tool description or handler, and no deterministic check reads tool "
                       "descriptions for instructions (tool_poisoning detects invisible unicode only)")
    return reasons


def _ratio(num: int, den: int) -> str:
    return f"{num}/{den}"


def score(rows: list[dict]) -> dict:
    """rows carry role (attack | control | calibration), verdict, flagged, any_flag. INCONCLUSIVE is never scored."""
    attacks = [r for r in rows if r["role"] == "attack" and r["verdict"] != "INCONCLUSIVE"]
    controls = [r for r in rows if r["role"] == "control" and r["verdict"] != "INCONCLUSIVE"]
    tp = sum(1 for r in attacks if r["flagged"])
    tp_any = sum(1 for r in attacks if r["any_flag"])
    fp = sum(1 for r in controls if r["flagged"])
    fp_any = sum(1 for r in controls if r["any_flag"])

    calibration = []
    for r in rows:
        if r["role"] != "calibration":
            continue
        if r["verdict"] == "INCONCLUSIVE":
            result = "INCONCLUSIVE"
        elif r["expect"] == "flag":
            result = "PASS" if r["flagged"] else "FAIL"
        else:
            result = "PASS" if not r["flagged"] else "FAIL"
        calibration.append({"name": r["name"], "expect": r["expect"], "verdict": r["verdict"], "result": result,
                            "findings": r["findings"]})

    return {
        "attacks_scored": len(attacks),
        "controls_scored": len(controls),
        "recall_confirmed": _ratio(tp, len(attacks)),
        "recall_any": _ratio(tp_any, len(attacks)),
        "precision_confirmed": _ratio(tp, tp + fp) if tp + fp else "undefined (no flags)",
        "precision_any": _ratio(tp_any, tp_any + fp_any) if tp_any + fp_any else "undefined (no flags)",
        "specificity_confirmed": _ratio(len(controls) - fp, len(controls)),
        "calibration": calibration,
        "calibration_passed": bool(calibration) and all(c["result"] == "PASS" for c in calibration),
        "inconclusive": sum(1 for r in rows if r["verdict"] == "INCONCLUSIVE"),
        "agent_susceptibility": "not produced in this scorecard; see scorecard A (kept separate)",
    }
