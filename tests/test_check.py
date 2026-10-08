"""`mcp-rt check` — the one-command complete assessment returns VULNERABLE on the vulnerable fixture
and CLEAN on the safe one. (--no-cap keeps it fast/deterministic in CI.)"""
import sys
from pathlib import Path

from hunt.check import _run_full_check

FIX = Path(__file__).resolve().parent.parent / "hunt" / "probe_fixtures"


def test_check_flags_vulnerable_server():
    rc = _run_full_check(f"{sys.executable} {FIX / 'vuln_server.py'}", do_cap=False)
    assert rc == 1   # vulnerable


def test_check_passes_safe_server():
    rc = _run_full_check(f"{sys.executable} {FIX / 'safe_server.py'}", do_cap=False)
    assert rc == 0   # clean
