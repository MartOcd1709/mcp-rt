"""Tier-B generality battery for #45 (path-traversal). Proves the probe covers the CWE-22/23 CLASS —
not the 2 trial CVE instances — against a synthetic server whose tool/param names appear NOWHERE in
probes.py (the FULLY-DYNAMIC gate). Each vuln tool must fire by ORACLE (our exact canary returned);
the confined control must stay CLEAN (the anti-false-positive anchor)."""
import asyncio
import sys
from pathlib import Path

import pytest

from hunt import probes as P

_FIXTURE = Path(P.__file__).resolve().parent / "probe_fixtures" / "pt_variants_server.py"
# names that MUST NOT be hardcoded in the probe — it has to discover them dynamically
_NOVEL = ("blob_read", "link_follow", "decode_fetch", "snap_capture", "safe_open", "doc-vault")


@pytest.fixture(scope="module")
def results():
    old = P._ALLOW_WRITE_INTO_ROOT
    P._ALLOW_WRITE_INTO_ROOT = True                 # we OWN this synthetic server -> opt in to the B (symlink) plant
    try:
        res = asyncio.run(P.scan_target([sys.executable, str(_FIXTURE)], probes=[P.probe_path_traversal]))
    finally:
        P._ALLOW_WRITE_INTO_ROOT = old
    return {r.tool: r for r in res}


def test_dynamic_gate_no_fixture_names_in_probe():
    src = Path(P.__file__).read_text()
    for n in _NOVEL:
        assert n not in src, f"probes.py hardcodes a fixture tool/server name ({n}) — not fully dynamic"


def test_sibling_prefix_fires(results):            # CVE-2025-53110 (the flagship #45 FN, server 1)
    r = results["blob_read"]
    assert r.verdict == P.VULNERABLE and "sibling-prefix" in r.rationale


def test_symlink_fires(results):                   # CVE-2025-53109 (opt-in B)
    r = results["link_follow"]
    assert r.verdict == P.VULNERABLE and "symlink" in r.rationale


def test_encoded_variant_fires(results):           # evasion coverage beyond the 2 CVE instances
    r = results["decode_fetch"]
    assert r.verdict == P.VULNERABLE and ("encoded" in r.rationale or "url-encoded" in r.rationale)


def test_output_dir_escape_fires(results):         # sub-gap C: internally-generated-content output tool
    r = results["snap_capture"]
    assert r.verdict == P.VULNERABLE


def test_confined_control_is_clean_no_fp(results):  # the anti-FP anchor — a correct server must stay CLEAN
    r = results["safe_open"]
    assert r.verdict == P.CLEAN


def test_confined_output_tool_no_fp(results):       # C must NOT false-positive on a confined output tool (the playwright case)
    r = results["safe_snap"]
    assert r.verdict == P.CLEAN


def test_every_result_oracle_or_nothing(results):   # path-traversal is binary: proof or not — never SUSPECTED
    for r in results.values():
        assert r.verdict in (P.VULNERABLE, P.CLEAN, P.INCONCLUSIVE, P.NOT_APPLICABLE)
        assert r.verdict != P.SUSPECTED
