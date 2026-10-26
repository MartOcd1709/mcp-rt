"""Tier-B generality battery for #58 (sql_injection). Proves the class-level grading on a synthetic server
whose tool/param names appear NOWHERE in probes.py (the FULLY-DYNAMIC gate), and — at runtime, not by
grepping source — that the probe sends only READ-ONLY payloads."""
import asyncio
import re
import sys
import types
from pathlib import Path

import pytest

from hunt import probes as P

_FIXTURE = Path(P.__file__).resolve().parent / "probe_fixtures" / "sqli_variants_server.py"
_NOVEL = ("ledger_find", "row_by_id", "boolean_lookup", "error_lookup", "count_rows", "ledger_sql",
          "echo_reject", "needle", "rowkey", "probe_key", "rowtag", "sql_text", "sql-ledger")
_DESTRUCTIVE = re.compile(r"(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|REPLACE|MERGE)", re.I)


@pytest.fixture(scope="module")
def results():
    res = asyncio.run(P.scan_target([sys.executable, str(_FIXTURE)], probes=[P.probe_sql_injection]))
    return {r.tool: r for r in res}


def test_dynamic_gate_no_fixture_names_in_probe():
    src = Path(P.__file__).read_text()
    for n in _NOVEL:
        assert n not in src, f"probes.py hardcodes a fixture tool/server/param name ({n}) — not fully dynamic"


def test_union_exfil_string_context_is_proof(results):   # PROOF: the per-run product came back
    r = results["ledger_find"]
    assert r.verdict == P.VULNERABLE and r.confirmation_method == "oracle" and "UNION" in r.evidence


def test_union_exfil_numeric_context_is_proof(results):  # numeric injection (no closing quote)
    r = results["row_by_id"]
    assert r.verdict == P.VULNERABLE and r.confirmation_method == "oracle"


def test_boolean_only_is_suspected_never_vulnerable(results):   # inference, never auto-confirmed
    r = results["boolean_lookup"]
    assert r.verdict == P.SUSPECTED and "boolean" in r.rationale and r.verdict != P.VULNERABLE


def test_error_only_is_suspected_never_vulnerable(results):     # inference, never auto-confirmed
    r = results["error_lookup"]
    assert r.verdict == P.SUSPECTED and "error-based" in r.rationale and r.verdict != P.VULNERABLE


def test_parameterized_is_clean_no_fp(results):                 # the critical anti-FP anchor
    r = results["count_rows"]
    assert r.verdict == P.CLEAN and r.confirmation_method in ("oracle_negative", "refusal")


def test_sql_executor_is_by_design_not_a_finding(results):      # a SQL runner runs SQL by design
    r = results["ledger_sql"]
    assert r.verdict == P.CLEAN and r.confirmation_method in ("by_design", "oracle_negative", "refusal")


def test_reflection_does_not_false_positive(results):           # reject + echo the payload -> CLEAN
    r = results["echo_reject"]
    assert r.verdict == P.CLEAN and r.verdict not in (P.VULNERABLE, P.SUSPECTED)


def test_no_suspected_on_a_proof_tool(results):                  # honesty: a proven tool is not a lead
    assert results["ledger_find"].verdict == P.VULNERABLE and results["row_by_id"].verdict == P.VULNERABLE


class _Rec:
    """A session that RECORDS every argument the probe sends and never answers — offline, runtime-true."""

    def __init__(self):
        self.sent: list[str] = []

    async def call_tool(self, name, args):
        self.sent.extend(str(v) for v in args.values())
        raise RuntimeError("recorded only")


def _tool(name, desc, param):
    return types.SimpleNamespace(name=name, description=desc,
                                 inputSchema={"type": "object", "properties": {param: {"type": "string"}},
                                              "required": [param]})


def test_only_read_only_payloads_are_sent():                    # Part A, checked at RUNTIME
    tools = [_tool("ledger_find", "Search the ledger table for labels containing a needle.", "needle"),
             _tool("row_by_id", "Fetch a label from the ledger table by row key.", "rowkey"),
             _tool("ledger_sql", "Execute a SQL query against the ledger database and return the rows.", "sql_text")]
    rec = _Rec()
    asyncio.run(P.probe_sql_injection(rec, tools))
    assert rec.sent, "probe sent nothing — the safety check would be vacuous"
    assert any("UNION SELECT" in s for s in rec.sent), "UNION recall payloads were not sent"
    bad = [s for s in rec.sent if _DESTRUCTIVE.search(s)]
    assert not bad, f"destructive SQL payload(s) sent to a target: {bad[:3]}"
