"""Phase 0 honesty spine — class-agnostic generality proof (Tier B).

Asserts the invariants, NOT any trial server / fixture tool name:
 - verdict_for() is total over the method vocabulary and is the SOLE verdict source;
 - VULNERABLE is reachable ONLY from a proof method (oracle/differential); inference → SUSPECTED;
 - a blocked test → INCONCLUSIVE, never a silent CLEAN; a recognized refusal → CLEAN;
 - every ProbeResult any probe emits carries a valid method and verdict == verdict_for(method).
"""
import asyncio
import sys
from pathlib import Path

import pytest

from hunt import probes as P


def test_verdict_for_is_total_and_correct():
    assert P.verdict_for("oracle") == P.VULNERABLE
    assert P.verdict_for("differential") == P.VULNERABLE
    assert P.verdict_for("signature") == P.SUSPECTED
    assert P.verdict_for("static") == P.SUSPECTED
    assert P.verdict_for("observed_change") == P.SUSPECTED
    assert P.verdict_for("oracle_negative") == P.CLEAN
    assert P.verdict_for("refusal") == P.CLEAN
    assert P.verdict_for("by_design") == P.CLEAN
    assert P.verdict_for("error") == P.INCONCLUSIVE
    assert P.verdict_for("not_applicable") == P.NOT_APPLICABLE


def test_verdict_is_derived_single_source():
    assert P.ProbeResult("x", "t", "signature").verdict == P.SUSPECTED
    with pytest.raises(TypeError):                     # a probe CANNOT inject a verdict — it is init=False
        P.ProbeResult("x", "t", "oracle", verdict="CLEAN")   # type: ignore[call-arg]


def test_unknown_method_raises():
    with pytest.raises(KeyError):
        P.verdict_for("VULNERABLE")                    # a raw verdict is not a confirmation method
    with pytest.raises(KeyError):
        P.ProbeResult("x", "t", "totally-made-up")


def test_proof_only_for_oracle_or_differential():
    assert {m for m, v in P._METHOD_VERDICT.items() if v == P.VULNERABLE} == {"oracle", "differential"}
    for m in ("signature", "static", "observed_change"):
        assert P.verdict_for(m) == P.SUSPECTED


def test_is_refusal_strict():
    for deny in ["Security violation: blocked", "executable 'git' not in allowed list",
                 "path is outside allowed roots", "403 Forbidden", "permission denied",
                 "validation failed", "access denied", "request was refused"]:
        assert P._is_refusal(deny), deny
    for notdeny in ["KeyError: 'x'", "TimeoutError", "", "connection closed",
                    "unexpected end of JSON input", "hello world", "McpError: Connection closed"]:
        assert not P._is_refusal(notdeny), notdeny


def test_negative_method_refusal_vs_error_vs_benign():
    assert P._negative_method(["ordinary tool output"], []) == "oracle_negative"   # oracle ran, nothing fired
    assert P._negative_method(["Security violation: blocked"], []) == "refusal"     # returned deny
    assert P._negative_method([], ["not in allowed list"]) == "refusal"             # raised deny
    assert P._negative_method([], ["TimeoutError"]) == "error"                      # blocked -> inconclusive
    assert P._negative_method([], []) == "error"                                    # never ran -> inconclusive
    # a real response present means the oracle ran -> CLEAN wins over any noise
    assert P._negative_method(["real output", "Security violation"], ["TimeoutError"]) == "oracle_negative"


def test_every_probe_result_routes_through_verdict_for():
    """Generality: no matter the probe or fixture, every result carries a mapped method and its verdict
    is exactly verdict_for(method) — the single-source invariant holds across ALL classes."""
    base = Path(P.__file__).resolve().parent / "probe_fixtures"
    for fx in ("vuln_server.py", "safe_server.py"):
        results = asyncio.run(P.scan_target([sys.executable, str(base / fx)]))
        assert results
        for r in results:
            assert r.confirmation_method in P._METHOD_VERDICT, (r.probe, r.confirmation_method)
            assert r.verdict == P.verdict_for(r.confirmation_method)
            assert r.verdict in (P.VULNERABLE, P.SUSPECTED, P.CLEAN, P.INCONCLUSIVE, P.NOT_APPLICABLE)
