"""SETUP_FAILED separation: a target that never ran is not folded into INCONCLUSIVE.

Guards the honest-denominator rule — reliability is "of servers that actually ran, what % did we
verdict", so install/config/bad-package failures get their own verdict and stay out of that ratio.
"""
import hunt.sweep as sweep
from hunt.findings_db import DB, VERDICTS


def test_classify_python_import_failure_is_broken_package():
    # mcp 1.x/2.x version skew: server imports an API our env doesn't provide. Was falling to OTHER.
    why = "ModuleNotFoundError: No module named 'mcp.server.fastmcp'. This is mcp 2.x"
    assert sweep._classify(why) == "BROKEN_PACKAGE"


def test_classify_ambiguous_executable_is_entrypoint_not_found():
    assert sweep._classify("The following executables are available:") == "ENTRYPOINT_NOT_FOUND"


def test_verdict_for_setup_vs_inconclusive():
    for cat in ("NEEDS_CONFIG", "INSTALL_FAILED", "ENTRYPOINT_NOT_FOUND",
                "NEEDS_SUBCOMMAND", "BROKEN_PACKAGE"):
        assert sweep._verdict_for(cat) == "SETUP_FAILED"
    for cat in ("SCAN_TIMEOUT", "OTHER"):      # server started / unknown -> genuinely inconclusive
        assert sweep._verdict_for(cat) == "INCONCLUSIVE"


def test_setup_failed_is_a_registered_verdict():
    assert "SETUP_FAILED" in VERDICTS


def test_scan_one_records_setup_failed(tmp_path, monkeypatch):
    # A target whose launch raises and whose diagnosis is a broken package -> SETUP_FAILED, not INCONCLUSIVE.
    def _boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(sweep, "run_full_scan", _boom)
    monkeypatch.setattr(sweep, "_resolve_launch", lambda c: c)
    monkeypatch.setattr(sweep, "prewarm", lambda c: None)
    monkeypatch.setattr(sweep, "_diagnose", lambda c: "No module named 'mcp.server.fastmcp'")
    db = DB(tmp_path / "t.db")
    r = sweep.scan_one({"name": "skew-mcp", "cmd": "x"}, db, timeout=5, source="test")
    db.close()
    assert r["verdict"] == "SETUP_FAILED" and r["cat"] == "BROKEN_PACKAGE"
