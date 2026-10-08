"""M6: fleet rollup + supply-chain risk flags (pure logic, no network)."""
from hunt.fleet import fleet_rollup, supply_risk


def test_supply_risk_flags():
    assert supply_risk({"maintainers": 1, "stale_days": 400, "weekly_downloads": 200000}) == \
        ["single-maintainer", "stale (400d)", "high-blast-radius (200000/wk)"]
    assert supply_risk({"maintainers": 5, "stale_days": 10, "weekly_downloads": 50}) == []
    assert supply_risk({}) == []                      # no metadata -> no flags (best-effort)
    assert supply_risk({"maintainers": 2}) == []      # 2 maintainers is not single


def test_fleet_rollup_aggregates():
    results = [
        {"name": "a", "verdict": "VULNERABLE", "findings": ["command_injection"], "supply_flags": ["single-maintainer"]},
        {"name": "b", "verdict": "VULNERABLE", "findings": ["command_injection", "sql_injection"], "supply_flags": []},
        {"name": "c", "verdict": "CLEAN", "findings": [], "supply_flags": []},
        {"name": "d", "verdict": "INCONCLUSIVE", "findings": [], "supply_flags": ["stale (500d)"]},
    ]
    r = fleet_rollup(results)
    assert r["total"] == 4 and r["scanned"] == 3 and r["vulnerable"] == 2 and r["inconclusive"] == 1
    assert r["by_class"] == {"command_injection": 2, "sql_injection": 1}
    assert r["servers_with_supply_risk"] == 2          # a and d
