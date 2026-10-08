"""Daily run-log writer: a dated log that captures every server's verdict + the run counts."""
from collections import Counter

import hunt.daily as daily


def test_write_run_log(tmp_path, monkeypatch):
    monkeypatch.setattr(daily, "RUNS_DIR", tmp_path)
    results = [
        {"name": "clean-mcp", "verdict": "CLEAN", "grade": "A", "score": 100, "findings": []},
        {"name": "vuln-mcp", "verdict": "VULNERABLE", "grade": "F", "score": 10,
         "findings": [{"cls": "path_traversal", "tool": "read_file"}]},
        {"name": "dead-mcp", "verdict": "INCONCLUSIVE", "cat": "INSTALL_FAILED", "why": "npm err 404"},
    ]
    path = daily._write_run_log("2026-10-05", results, Counter({"INSTALL_FAILED": 1}),
                                Counter({"path_traversal": 1}))
    from pathlib import Path
    text = Path(path).read_text()
    assert "scanned: **2**" in text and "inconclusive: **1**" in text and "vulnerable: **1**" in text
    assert "`clean-mcp`" in text and "path_traversal:read_file" in text and "[INSTALL_FAILED]" in text
    # timestamped filename so same-day runs don't clobber: "<date>_<HHMMSS>.md"
    assert Path(path).name.startswith("2026-10-05_") and path.endswith(".md")


def test_plan_three_lanes_dedup(monkeypatch):
    class FakeDB:
        def tested_names(self, within_days=None):
            return {"fresh-a"}           # already tested recently -> must be dropped from fresh
        def close(self):
            pass
    monkeypatch.setattr(daily, "DB", lambda: FakeDB())

    def fake_discover(queries, cap, max_downloads, min_downloads=10, maintained=True, popular=False):
        if popular:
            return [{"name": "pop-a", "cmd": "x"}, {"name": "pop-b", "cmd": "x"}]
        return [{"name": "fresh-a", "cmd": "x"}, {"name": "pop-b", "cmd": "x"},
                {"name": "fresh-c", "cmd": "x"}]
    monkeypatch.setattr(daily, "discover", fake_discover)

    top, popular, fresh, pypi = daily._plan(do_top=False, top_only=False, cap=10,
                                            retest_days=30, popular_cap=5, pypi_cap=0)  # pypi off = no network
    assert top == [] and pypi == []
    assert [t["name"] for t in popular] == ["pop-a", "pop-b"]
    # fresh-a is already tested (dropped); pop-b is in the popular lane (dropped) -> only fresh-c
    assert [t["name"] for t in fresh] == ["fresh-c"]


def test_pypi_discovery_filter(monkeypatch):
    import hunt.sweep as sweep
    # fixed name pool instead of the live PyPI simple index; all "live" instead of a JSON call
    monkeypatch.setattr(sweep, "_pypi_names", lambda: [
        "mcp-server-git", "postgres-mcp", "ai-browser-mcp",   # risky -> keep
        "mcp-proxy-py", "some-mcp-sdk",                        # plumbing -> drop (_SKIP_SUBSTR)
        "notes-mcp",                                           # mcp but not risky -> drop
    ])
    monkeypatch.setattr(sweep, "_pypi_maintained", lambda n: (True, "pypi live", "1.0.0"))
    out = [t["name"] for t in sweep.discover_pypi(cap=10, seen={"postgres-mcp"})]  # dedup drops postgres-mcp
    assert "mcp-server-git" in out and "ai-browser-mcp" in out
    assert "postgres-mcp" not in out            # deduped (already tested)
    assert "mcp-proxy-py" not in out and "some-mcp-sdk" not in out  # plumbing filtered
    assert "notes-mcp" not in out               # not a risky category
    assert all(t["cmd"].startswith("uvx ") for t in sweep.discover_pypi(cap=10, seen=set()))
