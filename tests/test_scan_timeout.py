"""scan_one timeout classification: a slow-but-started server -> SCAN_TIMEOUT, a fast crash -> not."""
import asyncio

import hunt.sweep as sweep
from hunt.findings_db import DB
from hunt.probes import ScanError


def _db(tmp_path):
    return DB(tmp_path / "t.db")


def test_slow_server_is_scan_timeout(tmp_path, monkeypatch):
    async def _slow(*a, **k):
        await asyncio.sleep(5)
    monkeypatch.setattr(sweep, "run_full_scan", _slow)
    monkeypatch.setattr(sweep, "_resolve_launch", lambda c: c)   # no real subprocess
    monkeypatch.setattr(sweep, "prewarm", lambda c: None)
    db = _db(tmp_path)
    r = sweep.scan_one({"name": "slow-mcp", "cmd": "x"}, db, timeout=1, source="test")
    db.close()
    assert r["verdict"] == "INCONCLUSIVE" and r["cat"] == "SCAN_TIMEOUT"


def test_fast_crash_is_not_scan_timeout(tmp_path, monkeypatch):
    async def _boom(*a, **k):
        raise ScanError("McpError: Connection closed")
    monkeypatch.setattr(sweep, "run_full_scan", _boom)
    monkeypatch.setattr(sweep, "_resolve_launch", lambda c: c)
    monkeypatch.setattr(sweep, "prewarm", lambda c: None)
    monkeypatch.setattr(sweep, "_diagnose", lambda c: "McpError: Connection closed")
    db = _db(tmp_path)
    r = sweep.scan_one({"name": "dead-mcp", "cmd": "x"}, db, timeout=1, source="test")
    db.close()
    assert r["verdict"] == "INCONCLUSIVE" and r["cat"] != "SCAN_TIMEOUT"
