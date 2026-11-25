"""Tier-B generality battery for telemetry_leak (CWE-532) and lethal_trifecta, plus their scorecard rules.

Both probes are target-driven: they run against synthetic servers whose tool / argument names appear NOWHERE in
probes.py, one tool per row of the scenario matrix (the proven cases, the leads, and every by-design case that must
stay quiet). The scorecard tests pin the honesty rule: a clean result from either class is PARTIAL, never PASS."""
import asyncio
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from hunt import probes as P
from hunt import report
from hunt.assess_complete import merge_compliance
from hunt.probes import ProbeResult

_FX = Path(P.__file__).resolve().parent / "probe_fixtures"
_TOKEN = "tok-9f3c1a7d5e2b4a60"          # the fixture's own service credential: private data the server holds
_NOVEL = ("vault_login", "link_service", "audit_trail", "refresh_grant", "open_session", "whoami", "translate_phrase",
          "lookup_city", "stash_memo", "keep_secret", "reveal_all", "svc-debug", "digest_bulletin", "pull_notices",
          "render_site", "grab_page", "pinned_fetch", "read_ledger", "BULLETIN_API_TOKEN", "ops-desk", "partner-desk")


def _scan(fixture: str, probe, *args: str) -> list:
    env = {**os.environ, "BULLETIN_API_TOKEN": _TOKEN}
    return asyncio.run(P.scan_target([sys.executable, str(_FX / fixture), *args], env=env, probes=[probe]))


@pytest.fixture(scope="module")
def telem():
    return {r.tool: r for r in _scan("telemetry_variants_server.py", P.probe_telemetry_leak)}


@pytest.fixture(scope="module")
def chain():
    return {r.tool: r for r in _scan("trifecta_variants_server.py", P.probe_lethal_trifecta)}


def test_dynamic_gate_no_fixture_names_in_probe():
    src = Path(P.__file__).read_text()
    for n in _NOVEL:
        assert n not in src, f"probes.py hardcodes a fixture tool/server/argument name ({n}) — not fully dynamic"


# ---- telemetry_leak: the proven tier (a SECRET-typed argument in a log / telemetry channel) -------------------------
@pytest.mark.parametrize("tool,channel", [("vault_login", "stderr"), ("link_service", "tool audit_trail"),
                                          ("refresh_grant", "MCP log notification")])
def test_secret_argument_in_a_log_channel_is_proven(telem, tool, channel):
    r = telem[tool]
    assert r.verdict == P.VULNERABLE and r.confirmation_method == "oracle"
    assert channel in r.evidence and r.marker.startswith("mcprt-telem-")


# ---- telemetry_leak: leads -------------------------------------------------------------------------------------
def test_secret_readable_back_through_an_ordinary_tool_is_a_lead(telem):
    r = telem["open_session"]            # also proves the read-back order: the reader runs before the writer is re-called
    assert r.verdict == P.SUSPECTED and "tool whoami" in r.evidence


def test_content_written_to_a_file_by_a_non_store_tool_is_a_lead(telem):
    r = telem["translate_phrase"]
    assert r.verdict == P.SUSPECTED and "svc-debug.log" in r.evidence


def test_arguments_logged_verbatim_are_one_server_level_lead(telem):
    r = telem["(server)"]
    assert r.verdict == P.SUSPECTED and "lookup_city.name" in r.evidence and "stderr" in r.evidence
    assert "lookup_city" not in telem     # one logging behaviour, not a lead per tool


# ---- telemetry_leak: by design / control works -> must stay quiet ------------------------------------------------
@pytest.mark.parametrize("tool", ["stash_memo", "keep_secret", "mirror", "sign_in"])
def test_by_design_storage_echo_and_redaction_stay_clean(telem, tool):
    assert telem[tool].verdict == P.CLEAN


def test_grade_matrix():
    g = P._telemetry_grade
    assert g(True, "log", False) == g(True, "log", True) == g(True, "telem", True) == "oracle"
    assert g(True, "file", False) == "oracle" and g(True, "file", True) == "cross_surface_echo"
    assert g(True, "other", False) == "cross_surface_echo" and g(True, "other", True) is None      # a vault
    assert g(False, "log", True) == g(False, "log", False) == "cross_surface_echo"
    assert g(False, "telem", False) == g(False, "file", False) == "cross_surface_echo"
    assert g(False, "telem", True) is None and g(False, "file", True) is None                       # commit -> history
    assert g(False, "other", False) is None                                                          # note -> list notes


def test_secret_argument_classifier():
    def tool(**props):
        return SimpleNamespace(name="t", description="", inputSchema={"type": "object", "properties": props})
    s = {"type": "string"}
    secret, content = P._plant_params(tool(accessToken=s, max_tokens={"type": "integer"}, passenger=s, pin=s, ping=s,
                                           author=s, mode={"type": "string", "enum": ["a"]},
                                           blob={"type": "string", "format": "password"}))
    assert set(secret) == {"accessToken", "pin", "blob"}          # not passenger / ping / author / the integer
    assert "mode" not in secret + content                         # an enum cannot carry a planted value


def test_no_plantable_argument_is_not_applicable():
    tool = SimpleNamespace(name="now", description="Current time.", inputSchema={"type": "object", "properties": {}})
    rows = asyncio.run(P.probe_telemetry_leak(None, [tool]))
    assert [r.verdict for r in rows] == [P.NOT_APPLICABLE]


# ---- lethal_trifecta: the chain --------------------------------------------------------------------------------
def test_full_chain_is_proven_and_never_prints_the_secret(chain):
    r = chain["digest_bulletin"]
    assert r.verdict == P.VULNERABLE and r.confirmation_method == "oracle"
    assert "BULLETIN_API_TOKEN" in r.evidence                     # names the variable ...
    assert _TOKEN not in r.evidence + r.rationale + r.marker      # ... never its value


def test_content_steered_request_without_private_data_is_a_lead(chain):
    r = chain["pull_notices"]
    assert r.verdict == P.SUSPECTED and r.confirmation_method == "partial_chain"


def test_renderer_loading_subresources_is_by_design(chain):
    assert chain["render_site"].verdict == P.CLEAN


def test_plain_fetch_and_refusal_are_clean(chain):
    assert chain["grab_page"].verdict == P.CLEAN
    assert chain["pinned_fetch"].confirmation_method == "refusal"


# ---- lethal_trifecta: composition ------------------------------------------------------------------------------
def test_all_three_legs_in_one_server_is_exposure_not_a_lead(chain):
    r = chain["(server)"]                # tools doing their advertised jobs: named, never flagged
    assert r.confirmation_method == "by_design" and r.verdict == P.CLEAN
    assert "read_ledger" in r.evidence and "(demonstrated)" in r.evidence
    assert "pinned_fetch" not in r.evidence                       # a tool that refused offers no live leg


def test_benign_calibration_server_raises_no_flag_from_these_classes():
    """The benchmark's benign server has a fetch tool and a file-read tool. Neither class may flag it."""
    rows = _scan("safe_server.py", P.probe_telemetry_leak) + _scan("safe_server.py", P.probe_lethal_trifecta)
    assert rows and not [r for r in rows if r.verdict in (P.VULNERABLE, P.SUSPECTED)]


def test_a_missing_leg_is_clean_and_named():
    rows = {r.tool: r for r in _scan("trifecta_variants_server.py", P.probe_lethal_trifecta, "--no-private-read")}
    r = rows["(server)"]
    assert r.verdict == P.CLEAN and "missing: private-data read" in r.rationale
    assert rows["digest_bulletin"].verdict == P.VULNERABLE        # the chain proof does not depend on the legs


def test_legs_from_tool_metadata_only():
    def tool(name, desc, **props):
        return SimpleNamespace(name=name, description=desc,
                               inputSchema={"type": "object", "properties": {k: {"type": "string"} for k in props}})
    fs = [tool("read_text", "Read a file from the workspace.", path=1), tool("save_text", "Write a file.", path=1)]
    legs = P._trifecta_legs(fs)
    assert legs["private-data read"] == ["read_text"] and not legs["external egress"]        # a filesystem server
    fetcher = [tool("get_page", "Fetches a URL from the internet.", url=1)]
    legs = P._trifecta_legs(fetcher)
    assert legs["external egress"] and legs["untrusted-content ingestion"] and not legs["private-data read"]
    assert all(P._trifecta_legs(fs + fetcher).values())                                      # together: the trifecta
    assert all(P._trifecta_legs([tool("sh", "Run a shell command and return its output.", cmd=1)]).values())
    assert not any(P._trifecta_legs([tool("now", "Current time in a timezone.", tz=1)]).values())


# ---- scorecard: these classes can FAIL or flag their control, never PASS it -----------------------------------------
def _scorecard(monkeypatch, rows, sealed=False) -> dict:
    async def fake_scan(argv, env=None, surface=None):
        return list(rows)

    async def fake_tokens(argv, env=None):
        return SimpleNamespace(verdict="CLEAN", passthrough=None, rationale="", transcript=[])

    monkeypatch.setattr(report, "scan_target", fake_scan)
    monkeypatch.setattr(report, "probe_token_passthrough", fake_tokens)
    rep = asyncio.run(report.run_full_scan(["python3", "no_such_server.py"], sealed=sealed))
    return {c["id"]: c for c in rep["compliance"]} | {"_coverage": rep["coverage"], "_mcp06": rep["mcp06"],
                                                       "_suspected": rep["suspected"]}


def _row(cls, method, tool="t"):
    return ProbeResult(cls, tool, method, rationale="r")


def test_a_clean_result_is_partial_with_a_reason_never_pass(monkeypatch):
    s = _scorecard(monkeypatch, [_row("telemetry_leak", "oracle_negative"),
                                 _row("lethal_trifecta", "oracle_negative", "(server)")])
    assert s["MCP08"]["status"] == "PARTIAL" and "audit trail" in s["MCP08"]["basis"]
    assert s["MCP06"]["status"] == "PARTIAL" and "agent" in s["MCP06"]["basis"]
    assert s["MCP10"]["status"] == "NOT TESTED"                   # a partial clean speaks to its primary control only


def test_a_proven_finding_fails_every_mapped_control(monkeypatch):
    s = _scorecard(monkeypatch, [_row("telemetry_leak", "oracle"), _row("lethal_trifecta", "oracle")])
    assert s["MCP08"]["status"] == s["MCP06"]["status"] == s["MCP10"]["status"] == "FAIL"
    assert "basis" not in s["MCP08"]


def test_a_lead_marks_only_the_primary_control(monkeypatch):
    s = _scorecard(monkeypatch, [_row("lethal_trifecta", "partial_chain", "fetcher"),
                                 _row("context_oversharing", "oracle_negative"),
                                 _row("telemetry_leak", "cross_surface_echo")])
    assert s["MCP06"]["status"] == "SUSPECTED" and s["MCP08"]["status"] == "SUSPECTED"
    assert s["MCP10"]["status"] == "PASS"                         # context_oversharing's own clean result stands


def test_three_legs_by_design_is_an_exposure_note_and_never_a_lead(monkeypatch):
    legs = ProbeResult("lethal_trifecta", "(server)", "by_design", evidence="private-data read: a; ...", rationale="r")
    s = _scorecard(monkeypatch, [legs])
    assert s["MCP06"]["status"] == "PARTIAL"                      # not SUSPECTED, not PASS
    assert s["_mcp06"]["exposed"] and "lethal-trifecta legs" in s["_mcp06"]["reasons"][0]
    assert not s["_suspected"]


def test_inconclusive_only_stays_not_tested_and_mixed_says_so(monkeypatch):
    s = _scorecard(monkeypatch, [_row("telemetry_leak", "error")])
    assert s["MCP08"]["status"] == "NOT TESTED"
    s = _scorecard(monkeypatch, [_row("telemetry_leak", "error", "a"), _row("telemetry_leak", "oracle_negative", "b")])
    assert s["MCP08"]["status"] == "PARTIAL" and "could not be tested" in s["MCP08"]["basis"]


def test_sealed_run_never_clears_the_chain_test(monkeypatch):
    s = _scorecard(monkeypatch, [_row("lethal_trifecta", "oracle_negative", "fetcher"),
                                 _row("lethal_trifecta", "oracle_negative", "(server)")], sealed=True)
    by_tool = {c["tool"]: c["verdict"] for c in s["_coverage"] if c["cls"] == "lethal_trifecta"}
    assert by_tool == {"fetcher": P.INCONCLUSIVE, "(server)": P.CLEAN}   # the recorder is unreachable under the seal


def test_engagement_merge_keeps_the_partial_rule():
    base = [{"id": "MCP06", "title": "t", "status": "PARTIAL", "basis": "b"},
            {"id": "MCP10", "title": "t", "status": "PASS"}]
    lead = merge_compliance(base, [], [{"kind": "lethal_trifecta"}])
    assert lead[0] == {"id": "MCP06", "title": "t", "status": "SUSPECTED"} and lead[1]["status"] == "PASS"
    proven = merge_compliance(base, [{"cls": "lethal_trifecta"}], [])
    assert [c["status"] for c in proven] == ["FAIL", "FAIL"]
    assert merge_compliance(base, [], [])[0]["basis"] == "b"      # untouched status keeps its reason
