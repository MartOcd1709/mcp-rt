"""B1: the mass sweep runs every target through the Unit-3 seal (fail-closed) with the egress oracle merged.
Seal-gated (needs a rootless namespace); offline — local calibration fixtures only, no discovery/network."""
import json
import sys
from pathlib import Path

import pytest

from tests.seal_capability import SEAL_REASON, can_seal

pytestmark = pytest.mark.skipif(not can_seal(), reason=SEAL_REASON)

from hunt import sweep
from hunt.findings_db import DB

REPO = Path(__file__).resolve().parents[1]
CAL = REPO / "hunt" / "probe_fixtures"


def _scan(path, tmp_path, name):
    db = DB(str(tmp_path / "ledger.db"))
    try:
        return sweep.scan_one({"name": name, "cmd": f"{sys.executable} {path}"}, db, timeout=150)
    finally:
        db.close()


def test_sealed_sweep_flags_vuln_fixture(tmp_path):
    # vuln_server carries real impl bugs (cmd injection / path traversal / …). Sealed sweep must confirm it
    # AND prove the seal (sealed=True), with no host fallback.
    r = _scan(CAL / "vuln_server.py", tmp_path, "vuln-fixture")
    assert r.get("sealed") is True, r
    assert r["verdict"] == "VULNERABLE", r
    # R6 honesty: ssrf / context_oversharing cannot confirm under the seal (host sink / env canary
    # unreachable) -> their negative is INCONCLUSIVE, NEVER a sealed false-CLEAN.
    rep = json.loads((Path(r["report_dir"]) / "report.json").read_text())
    seal_inc = {c["verdict"] for c in rep.get("coverage", []) if c["cls"] in ("ssrf", "context_oversharing")}
    assert "CLEAN" not in seal_inc, seal_inc


def test_sealed_sweep_clean_fixture_not_falsely_vulnerable(tmp_path):
    # safe_server does its tools correctly -> must NOT be VULNERABLE (CLEAN or INCONCLUSIVE are both honest).
    r = _scan(CAL / "safe_server.py", tmp_path, "safe-fixture")
    assert r.get("verdict") != "VULNERABLE", r
