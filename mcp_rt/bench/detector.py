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
# Scorecard text only, never read by a verdict. Corpus classes ruled out of Unit 1 by the CIO. They stay in the table.
SCOPE_NOTES = {
    "tool_annotation": "out of Unit 1 scope (CIO ruling): a false-trust annotation needs observed egress to confirm, "
                       "which is Unit 2 + Unit 3",
    "elicitation_prompt": "out of Unit 1 scope (CIO ruling): runtime elicitation text needs a runtime/elicitation unit",
}


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
    """Why a lure class is not flagged, derived from the fixture's protocol features (data, never names). The last
    reason is the most specific one; the scorecard prints it."""
    features = set(protocol_features or [])
    reasons = ["lure_text reads this text statically (SUSPECTED ceiling); a miss means the phrasing sits outside the "
               "rule families: a coverage limit, reported, never a verdict"]
    if "elicitation" in features:
        reasons.append("the lure text exists only at call time (an elicitation request); the static scan sees schema "
                       "text only, so runtime text needs a runtime/elicitation unit")
    return reasons


def reasons_for(name: str, protocol_features) -> list[str]:
    """Scorecard text: gap_reasons plus any CIO scope ruling for this corpus class. Reporting only, never a verdict."""
    reasons = gap_reasons(protocol_features)
    if name in SCOPE_NOTES:
        reasons.append(SCOPE_NOTES[name])
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
