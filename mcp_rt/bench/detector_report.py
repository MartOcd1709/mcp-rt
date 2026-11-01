"""Write results_B.json and scorecard_B.md: detector precision/recall. Separate files from scorecard A, never blended."""
import json
from pathlib import Path

from .detector import CONTROL_NOTES, ENTRYPOINT, EXCLUDED, SCOPE_NOTES, TAINT_NOTE


def _flag_mark(flagged: bool, any_flag: bool) -> str:
    if flagged:
        return "yes (confirmed)"
    return "yes (lead only)" if any_flag else "no"


def _coverage_text(coverage: dict) -> str:
    """How many detector probes ran against this target, and what they concluded (evidence the probes were exercised)."""
    if not coverage:
        return "none"
    return ", ".join(f"{verdict} {count}" for verdict, count in sorted(coverage.items()))


def _why(r: dict) -> str:
    """The Why column. A lead is not a miss: it says the lure was matched and that confirming it needs other evidence.
    For a miss, reasons[-1] is already the most specific reason (the CIO scope note is appended by reasons_for)."""
    if r["flagged"]:
        return ""
    if r["any_flag"]:
        scope = SCOPE_NOTES.get(r["name"], "")
        return "lead: static text matched, not confirmed (not a verdict)" + (f"; {scope}" if scope else "")
    return r["reasons"][-1]


def _attack_section(rows: list[dict]) -> list[str]:
    attacks = [r for r in rows if r["role"] == "attack"]
    lines = ["| Attack | Subtlety | Flagged (confirmed) | Flagged (incl. leads) | Classes fired | Probe coverage | "
             "Why not flagged |", "|---|---|---|---|---|---|---|"]
    for r in attacks:
        fired = ", ".join(r["findings"] + [f"{c} (lead)" for c in r["leads"]]) or "none"
        lines.append(f"| `{r['name']}` | {r.get('subtlety', '?')} | {_flag_mark(r['flagged'], r['any_flag'])} | "
                     f"{'yes' if r['any_flag'] else 'no'} | {fired} | {_coverage_text(r['coverage'])} | {_why(r)} |")
    return lines


def _control_section(rows: list[dict]) -> list[str]:
    controls = [r for r in rows if r["role"] == "control"]
    lines = ["| Control | Mirrors | Flagged | Classes fired | Probe coverage |", "|---|---|---|---|---|"]
    for r in controls:
        fired = ", ".join(r["findings"] + [f"{c} (lead)" for c in r["leads"]]) or "none"
        lines.append(f"| `{r['name']}` | {r.get('cousin', '?')} | {_flag_mark(r['flagged'], r['any_flag'])} | "
                     f"{fired} | {_coverage_text(r['coverage'])} |")
    return lines


def _control_notes(rows: list[dict]) -> list[str]:
    """Every control lead must be documented. A confirmed control flag, or an undocumented lead, is flagged loudly."""
    out = []
    for r in rows:
        if r["role"] != "control":
            continue
        if r["flagged"]:
            out.append(f"- `{r['name']}`: **CONFIRMED false positive (VULNERABLE tier). Investigate before merge.**")
        elif r["any_flag"]:
            note = CONTROL_NOTES.get(r["name"])
            out.append(f"- `{r['name']}`: " + (note if note else "**UNDOCUMENTED lead: investigate before merge.**"))
    return out


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
          "The Why column marks a lead as not confirmed, and gives a miss its coverage limit or CIO scope ruling.", "",
          "## Precision and specificity — controls", ""]
    L += _control_section(rows)
    notes = _control_notes(rows)
    if notes:
        L += ["", "**Control leads and confirmed flags:**", ""] + notes
    L += ["", f"**Precision:** confirmed {scores['precision_confirmed']} · including leads {scores['precision_any']}",
          f"**Specificity (controls cleared):** {scores['specificity_confirmed']}", "",
          "When nothing is flagged, precision is undefined and cleared controls say nothing positive about the detector. "
          "Specificity alone is not evidence here.", "",
          "## Calibration: the detector's own reference fixtures (outside the corpus totals)", ""]
    L += _calibration_section(scores)
    L += ["", f"**Calibration: {cal}.**", "",
          "## Reading this", "",
          "- Lure text is read statically by the lure_text probe: tool, parameter, annotation, resource and prompt text. "
          "Its ceiling is SUSPECTED, never a confirmed finding.",
          "- Soft-wrapped text is read as one sentence. List items and blank lines stay boundaries (CIO-approved parser rule).",
          "- CIO ruling: the leads in the table above are the static ceiling for this corpus. Each attack without a lead is listed with its reason "
          "in the Why column, drawn from the CIO rulings file: out of static-lure scope, out of Unit 1 scope, or a lead "
          "whose confirmation needs a later unit.",
          "- A control lead is documented only where the control shares an attack's exact description sentence (a text "
          "twin). The documented control leads are listed above, from the rulings file. Control text is never changed, and "
          "the confirmed tier stays at 0 false positives.",
          "- Known limits this scorecard does not close: the canary observability gap (each attack forwards to MCPRT_CANARY, "
          "a loopback channel the detector does not observe, so a class proven by a forward cannot be confirmed here) and "
          "the family-B model mismatch (token passthrough tests a server's own environment credential, not an "
          "agent-supplied lure).",
          "- These corpus numbers are fit-to-corpus: the rule families were designed with these fixtures in view. "
          "Generalization evidence comes from an independent battery written from the threat model (CIO verification), not "
          "from this corpus or from the repo's held-out guard (tests/test_lure_heldout.py, written by the same author).",
          "- Residual known gaps, documented and not chased in Unit 1: (a) a bare destination handoff with no stated source, such as "
          "'place your session token into the field', does not fire, because the sourced-handoff rule needs the credential's "
          "origin in the agent's own context; (b) a passive declarative requirement, such as 'once the token is supplied', is a "
          "phrasing the rule families do not cover, with no measured precision boundary; confirming it needs behavior, so it belongs to Unit 3.",
          "- Not in this scorecard: agent susceptibility (ASR). That is scorecard A, and the two are never blended.",
          f"- INCONCLUSIVE targets: {scores['inconclusive']}. They are excluded from every rate and never counted as cleared.",
          ""]
    return "\n".join(L)


def write(out_dir: Path, meta: dict, scores: dict, rows: list[dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results_B.json").write_text(
        json.dumps({"meta": meta, "scores": scores, "targets": rows}, indent=2) + "\n")
    (out_dir / "scorecard_B.md").write_text(_markdown(meta, scores, rows))
