"""Write results_B.json and scorecard_B.md: detector precision/recall. Separate files from scorecard A, never blended."""
import json
from pathlib import Path

from .detector import ENTRYPOINT, EXCLUDED, TAINT_NOTE


def _flag_mark(flagged: bool, any_flag: bool) -> str:
    if flagged:
        return "yes (confirmed)"
    return "yes (lead only)" if any_flag else "no"


def _coverage_text(coverage: dict) -> str:
    """How many detector probes ran against this target, and what they concluded (evidence the probes were exercised)."""
    if not coverage:
        return "none"
    return ", ".join(f"{verdict} {count}" for verdict, count in sorted(coverage.items()))


def _attack_section(rows: list[dict]) -> list[str]:
    attacks = [r for r in rows if r["role"] == "attack"]
    lines = ["| Attack | Subtlety | Flagged (confirmed) | Flagged (incl. leads) | Classes fired | Probe coverage | "
             "Why not flagged |", "|---|---|---|---|---|---|---|"]
    for r in attacks:
        fired = ", ".join(r["findings"] + [f"{c} (lead)" for c in r["leads"]]) or "none"
        why = "" if r["flagged"] else r["reasons"][-1]
        lines.append(f"| `{r['name']}` | {r.get('subtlety', '?')} | {_flag_mark(r['flagged'], r['any_flag'])} | "
                     f"{'yes' if r['any_flag'] else 'no'} | {fired} | {_coverage_text(r['coverage'])} | {why} |")
    return lines


def _control_section(rows: list[dict]) -> list[str]:
    controls = [r for r in rows if r["role"] == "control"]
    lines = ["| Control | Mirrors | Flagged | Classes fired | Probe coverage |", "|---|---|---|---|---|"]
    for r in controls:
        fired = ", ".join(r["findings"] + [f"{c} (lead)" for c in r["leads"]]) or "none"
        lines.append(f"| `{r['name']}` | {r.get('cousin', '?')} | {_flag_mark(r['flagged'], r['any_flag'])} | "
                     f"{fired} | {_coverage_text(r['coverage'])} |")
    return lines


def _calibration_section(scores: dict) -> list[str]:
    lines = ["| Fixture | Expected | Verdict | Classes fired | Result |", "|---|---|---|---|---|"]
    for c in scores["calibration"]:
        fired = ", ".join(c["findings"]) or "none"
        lines.append(f"| `{c['name']}` | {c['expect']} | {c['verdict']} | {fired} | **{c['result']}** |")
    return lines


def _markdown(meta: dict, scores: dict, rows: list[dict]) -> str:
    cal = "PASS" if scores["calibration_passed"] else "FAIL"
    L = ["# Phase B scorecard B — detector precision/recall (mcp-rt deterministic detector)", "",
         f"Run `{meta['run_id']}` · git `{meta['git_sha']}` · {scores['attacks_scored']} attacks, "
         f"{scores['controls_scored']} controls scored · offline, no model, no network", "",
         f"**Entrypoint:** {ENTRYPOINT}",
         f"**Excluded:** {'; '.join(EXCLUDED)}",
         f"**Runtime taint monitor:** {TAINT_NOTE}",
         "**Flag:** primary = a confirmed finding (VULNERABLE). Leads (SUSPECTED) are a separate tier. MCP06 exposure "
         "is posture, not a flag, and is never counted.",
         "**Ground truth:** attacks should be flagged; controls should be cleared (each control mirrors an attack cousin).", "",
         "## Detector recall — attacks (one fixture per class)", ""]
    L += _attack_section(rows)
    L += ["", f"**Recall:** confirmed {scores['recall_confirmed']} · including leads {scores['recall_any']}", "",
          "The last column gives the reason a target was not flagged: a coverage limit (phrasing outside the rule families, or a lure in server behavior), or a "
          "CIO scope ruling for classes outside Unit 1.", "",
          "## Precision and specificity — controls", ""]
    L += _control_section(rows)
    L += ["", f"**Precision:** confirmed {scores['precision_confirmed']} · including leads {scores['precision_any']}",
          f"**Specificity (controls cleared):** {scores['specificity_confirmed']}", "",
          "When nothing is flagged, precision is undefined and cleared controls say nothing positive about the detector. "
          "Specificity alone is not evidence here.", "",
          "## Calibration: the detector's own reference fixtures (outside the corpus totals)", ""]
    L += _calibration_section(scores)
    L += ["", f"**Calibration: {cal}.**", "",
          "## Reading this", "",
          "- Lure text is read statically by the lure_text probe: tool, parameter, annotation, resource and prompt text. "
          "Its ceiling is SUSPECTED. A miss means either a phrasing outside the rule families or a lure that lives in server "
          "behavior, which model-facing text cannot show. Both are coverage limits, not verdicts.",
          "- Known limits this scorecard does not close: the canary observability gap (each attack forwards to MCPRT_CANARY, "
          "a loopback channel the detector does not observe, so a class proven by a forward cannot be confirmed here) and "
          "the family-B model mismatch (token passthrough tests a server's own environment credential, not an "
          "agent-supplied lure).",
          "- Out of Unit 1 scope by CIO ruling, kept in the table and not forced: tool_annotation (Unit 2 + Unit 3) and "
          "elicitation_prompt (runtime elicitation unit).",
          "- These corpus numbers are fit-to-corpus: the rule families were designed with these fixtures in view. The "
          "generalization evidence is the class-derived battery (tests/test_lure_heldout.py, run with pytest).",
          "- Not in this scorecard: agent susceptibility (ASR). That is scorecard A, and the two are never blended.",
          f"- INCONCLUSIVE targets: {scores['inconclusive']}. They are excluded from every rate and never counted as cleared.",
          ""]
    return "\n".join(L)


def write(out_dir: Path, meta: dict, scores: dict, rows: list[dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results_B.json").write_text(
        json.dumps({"meta": meta, "scores": scores, "targets": rows}, indent=2) + "\n")
    (out_dir / "scorecard_B.md").write_text(_markdown(meta, scores, rows))
