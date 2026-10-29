"""Scorecard B: mcp-rt's deterministic detector, precision and recall. Kept separate from scorecard A (ASR).

The arithmetic is pinned on synthetic rows, so a counting error fails here rather than in a published number.
The calibration test runs the real entrypoint on the detector's own reference fixtures: it must flag vuln_server and
clear safe_server. Without that, a zero-recall result could be a broken detector instead of a coverage gap.
"""
import shutil
import sqlite3
from pathlib import Path

from mcp_rt.bench import cli, detector
from mcp_rt.bench.detector_report import _markdown

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"


def _row(role, name, *, flagged=False, any_flag=None, verdict=None, expect=None):
    any_flag = flagged if any_flag is None else any_flag
    verdict = verdict or ("VULNERABLE" if flagged else ("SUSPECTED" if any_flag else "CLEAN"))
    return {"role": role, "name": name, "flagged": flagged, "any_flag": any_flag, "verdict": verdict,
            "findings": ["ssrf"] if flagged else [], "leads": [] if flagged or not any_flag else ["sql_injection"],
            "coverage": {"CLEAN": 3}, "reasons": ["a reason"], "subtlety": "low", "cousin": "x",
            "expect": expect, "error": None}


def test_calibration_flags_the_native_vulnerable_fixture_and_clears_the_safe_one():
    vuln = detector.scan_target(detector.CALIBRATION_DIR / "vuln_server.py")
    safe = detector.scan_target(detector.CALIBRATION_DIR / "safe_server.py")
    assert vuln["flagged"] and vuln["verdict"] == "VULNERABLE"
    assert not safe["flagged"] and not safe["any_flag"]


def test_recall_and_precision_are_counted_separately_and_correctly():
    rows = [
        _row("attack", "a_flagged", flagged=True),
        _row("attack", "a_lead_only", flagged=False, any_flag=True),
        _row("attack", "a_missed"),
        _row("control", "c_cleared"),
        _row("control", "c_false_alarm", flagged=True),
        _row("calibration", "vuln_server", flagged=True, expect="flag"),
        _row("calibration", "safe_server", flagged=False, expect="clear"),
    ]
    s = detector.score(rows)
    assert s["recall_confirmed"] == "1/3"          # 1 of 3 attacks flagged with a confirmed finding
    assert s["recall_any"] == "2/3"                # 2 of 3 with leads counted
    assert s["precision_confirmed"] == "1/2"      # 1 true flag, 1 false flag
    assert s["precision_any"] == "2/3"            # 2 true (lead-inclusive), 1 false
    assert s["specificity_confirmed"] == "1/2"    # 1 of 2 controls cleared
    assert s["calibration_passed"] is True


def test_precision_is_undefined_when_nothing_is_flagged_not_a_perfect_score():
    rows = [_row("attack", "a"), _row("control", "c")]
    s = detector.score(rows)
    assert s["precision_confirmed"] == "undefined (no flags)"
    assert s["recall_confirmed"] == "0/1"


def test_inconclusive_targets_are_excluded_from_every_rate():
    rows = [_row("attack", "a", verdict="INCONCLUSIVE"), _row("control", "c")]
    s = detector.score(rows)
    assert s["attacks_scored"] == 0
    assert s["inconclusive"] == 1


def test_a_failed_calibration_is_reported_as_failed():
    rows = [_row("calibration", "vuln_server", flagged=False, expect="flag"),
            _row("calibration", "safe_server", flagged=False, expect="clear")]
    s = detector.score(rows)
    assert not s["calibration_passed"]
    assert [c["result"] for c in s["calibration"]] == ["FAIL", "PASS"]


def test_gap_reasons_follow_the_fixture_protocol_features():
    shared = detector.gap_reasons([])
    assert any("observability gap" in r for r in shared)
    assert any("model mismatch" in r for r in shared)
    assert any("elicitation" in r for r in detector.gap_reasons(["tools", "elicitation"]))
    assert any("resource text" in r for r in detector.gap_reasons(["resources", "tools"]))
    assert any("tool description" in r for r in detector.gap_reasons(["tools"]))


def test_scorecard_b_never_renders_the_asr_figures():
    rows = [_row("attack", "a"), _row("control", "c"), _row("calibration", "vuln_server", flagged=True, expect="flag"),
            _row("calibration", "safe_server", flagged=False, expect="clear")]
    text = _markdown({"run_id": "r", "git_sha": "s"}, detector.score(rows), rows)
    assert "Agent susceptibility (ASR) — attacks" not in text
    assert "ASR cells" not in text
    assert "Detector recall" in text and "Calibration" in text


def test_detect_run_writes_separate_outputs_and_kind_detector_rows(tmp_path):
    fixtures = tmp_path / "fixtures"
    shutil.copytree(FIXTURES / "proxy_aggregator", fixtures / "proxy_aggregator")
    shutil.copytree(FIXTURES / "_controls" / "benign_routing", fixtures / "_controls" / "benign_routing")
    out, db = tmp_path / "out", tmp_path / "bench.db"
    code = cli.main(["detect", "--fixtures", str(fixtures), "--out", str(out), "--db", str(db)])
    assert code == 0                                       # calibration passes, so the exit code is clean
    assert (out / "scorecard_B.md").is_file() and (out / "results_B.json").is_file()
    assert not (out / "scorecard.md").exists()             # never overwrites or mixes with scorecard A's output
    conn = sqlite3.connect(str(db))
    kinds = [r[0] for r in conn.execute("SELECT kind FROM runs")]
    assert kinds and set(kinds) == {"detector"}            # bench.db rows are tagged kind='detector'
    assert len(kinds) == 4                                 # 1 attack + 1 control + 2 calibration
    conn.close()
