"""Tier-B generality battery for #51 (command_injection). Proves the interpreter-carrier + returned-text
nonce oracle catches the allowlist-bypass CLASS, the two zero-FP guards hold (anti-reflection oracle +
tightened restriction classifier), and the probe is FULLY DYNAMIC (tool/param names appear NOWHERE in
probes.py). Synthetic server, novel names; the mcp-shell live anchor is verified separately by the CIO."""
import asyncio
import sys
from pathlib import Path

import pytest

from hunt import probes as P

_FIXTURE = Path(P.__file__).resolve().parent / "probe_fixtures" / "cmdi_variants_server.py"
_NOVEL = ("gated_run", "open_shell", "echo_guard", "strict_run", "cmd-vault", "instruction")


@pytest.fixture(scope="module")
def results():
    res = asyncio.run(P.scan_target([sys.executable, str(_FIXTURE)], probes=[P.probe_command_injection]))
    return {r.tool: r for r in res}


def test_dynamic_gate_no_fixture_names_in_probe():
    src = Path(P.__file__).read_text()
    for n in _NOVEL:
        assert n not in src, f"probes.py hardcodes a fixture tool/server/param name ({n}) — not fully dynamic"


def test_interpreter_carrier_bypass_fires(results):      # CVE-2026-55581/55582 — the server-2 FN, now caught
    r = results["gated_run"]
    assert r.verdict == P.VULNERABLE and "bypassable" in r.rationale


def test_by_design_executor_stays_clean(results):        # benign "Safely" must NOT mis-class as a bypass (CHANGE 2)
    r = results["open_shell"]
    assert r.verdict == P.CLEAN and r.confirmation_method == "by_design"


def test_reflection_does_not_false_positive(results):    # reject+reflect must stay CLEAN (CHANGE 1, anti-reflection)
    r = results["echo_guard"]
    assert r.verdict == P.CLEAN


def test_refusal_is_clean(results):                      # a recognized deny -> CLEAN(refusal), never a fire
    r = results["strict_run"]
    assert r.verdict == P.CLEAN


def test_oracle_or_by_design_no_suspected(results):      # command_injection is oracle-gated — never SUSPECTED
    for r in results.values():
        assert r.verdict != P.SUSPECTED
        assert r.verdict in (P.VULNERABLE, P.CLEAN, P.INCONCLUSIVE, P.NOT_APPLICABLE)
