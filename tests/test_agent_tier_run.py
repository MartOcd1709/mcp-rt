"""Agent tier end to end, against real lab fixtures inside the real seal. Seal-gated: skipped where a
rootless namespace can't be built (CI), run everywhere it can.

Shows the headline honestly: the deterministic planner drives closed-space actions, the floor/egress oracle
decides, every VULNERABLE is re-demonstrated, controls stay CLEAN, and the target never leaves the seal.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_rt.agent_tier.run import assess
from tests.seal_capability import SEAL_REASON, can_seal

pytestmark = pytest.mark.skipif(not can_seal(), reason=SEAL_REASON)

REPO = Path(__file__).resolve().parents[1]
FIX = REPO / "fixtures"
CAL = REPO / "hunt" / "probe_fixtures"
FUTURE = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


def _roe(tmp, server_path, classes, tools, **over):
    doc = {"roe_version": 1,
           "target": {"id": "lab", "argv": [sys.executable, str(server_path)]},
           "classes": classes, "surface": {"tools": tools},
           "mode": "offline", "budget": {"max_actions": over.pop("max_actions", 20)},
           "authorized_by": "ved", "expires_at": FUTURE}
    doc.update(over)
    p = tmp / "roe.json"
    p.write_text(json.dumps(doc))
    return p


def test_egress_attack_is_proven_and_reproduced(tmp_path):
    rep = assess(_roe(tmp_path, FIX / "egress_evasion" / "server.py", ["egress"], ["check_for_updates"]))
    assert rep["stop_reason"] == "COMPLETE"
    assert len(rep["proven"]) == 1, rep
    f = rep["proven"][0]
    assert f["class"] == "egress" and f["method"] == "oracle" and f["reproduced"] is True


def test_benign_control_stays_clean(tmp_path):
    rep = assess(_roe(tmp_path, CAL / "safe_server.py", ["egress"], None, surface={"tools": []}))
    # safe_server exposes no network tool; discovered surface is used. No egress -> cleared, never a finding.
    assert rep["proven"] == [] and rep["leads"] == []
    assert all(r["method"] in ("sandbox_no_egress",) for r in rep["cleared"]) or rep["cleared"] == []


def test_benign_update_check_control_is_clean(tmp_path):
    rep = assess(_roe(tmp_path, FIX / "_controls" / "benign_update_check" / "server.py",
                      ["egress"], ["check_for_updates"]))
    assert rep["proven"] == []
    assert len(rep["cleared"]) == 1 and rep["cleared"][0]["method"] == "sandbox_no_egress"


def test_command_injection_proven_via_run_probe(tmp_path):
    # restricted_cmd advertises an allowlist; bypassing it and running a carrier is a real finding.
    rep = assess(_roe(tmp_path, CAL / "vuln_server.py", ["command_injection"], ["restricted_cmd"]))
    assert len(rep["proven"]) == 1 and rep["proven"][0]["class"] == "command_injection"
    assert rep["proven"][0]["method"] == "oracle" and rep["proven"][0]["reproduced"] is True


def test_declared_command_executor_is_by_design_not_a_finding(tmp_path):
    # run_cmd's declared purpose IS running a command (like a fetcher reaching a URL): by_design, CLEAN —
    # the oracle-vs-by-design precision, the same lesson as the SSRF fix. Not every executed command is a vuln.
    rep = assess(_roe(tmp_path, CAL / "vuln_server.py", ["command_injection"], ["run_cmd"]))
    assert rep["proven"] == []
    assert len(rep["cleared"]) == 1 and rep["cleared"][0]["method"] == "by_design"


def test_xxe_file_read_proven_under_seal(tmp_path):
    # import_profile parses attacker XML with external entities on. The file-read oracle reads OUR planted
    # nonce via a file:// entity — the seal is a net namespace (shared fs), so this CONFIRMS under the seal.
    # (OOB-via-XXE reach is removed by the seal and is covered by the egress class, same as R6 for ssrf.)
    rep = assess(_roe(tmp_path, CAL / "vuln_server.py", ["xxe"], ["import_profile"]))
    assert len(rep["proven"]) == 1 and rep["proven"][0]["class"] == "xxe", rep
    assert rep["proven"][0]["method"] == "oracle" and rep["proven"][0]["reproduced"] is True


def test_oob_only_xxe_under_seal_is_inconclusive_not_clean(tmp_path):
    # An OOB-only XXE (fetches an external entity, never returns the content) can't be caught by the file-read
    # oracle, and the OOB sink is unreachable under the seal while run_egress drives only benign args. It must
    # be INCONCLUSIVE (sandbox_unobservable), NEVER a silent CLEAN — proving the tool is not cleared.
    rep = assess(_roe(tmp_path, FIX / "xxe_oob" / "server.py", ["xxe"], ["import_doc"]))
    assert rep["proven"] == [] and rep["cleared"] == [], rep
    assert any(r["class"] == "xxe" and r["method"] == "sandbox_unobservable"
               for r in rep["inconclusive"]), rep


def test_action_budget_stops_the_run(tmp_path):
    rep = assess(_roe(tmp_path, FIX / "egress_evasion" / "server.py", ["egress"], ["check_for_updates"],
                      max_actions=1))
    assert rep["stop_reason"] == "BUDGET_ACTIONS" and rep["coverage"]["actions_used"] <= 1


def test_ssrf_under_seal_is_inconclusive_not_clean(tmp_path):
    # R6: probe_ssrf's host sink is unreachable inside the seal, so it can never CONFIRM here. It must be
    # INCONCLUSIVE, never a silent CLEAN. vuln_server's web_fetch would be a fetcher; import_from_url an SSRF —
    # either way, under the seal the dedicated ssrf probe cannot clear them.
    rep = assess(_roe(tmp_path, CAL / "vuln_server.py", ["ssrf"], ["import_from_url"]))
    assert rep["cleared"] == [] and rep["proven"] == []
    assert any(r["method"] == "probe_seal_incompatible" for r in rep["inconclusive"]), rep
