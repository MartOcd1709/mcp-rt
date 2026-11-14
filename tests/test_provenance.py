"""Provenance lane calibration battery (static repo-provenance detection).

Each fixture is a STATIC repo tree under tests/fixtures/provenance/ with BENIGN stand-ins only
(no live malware, no real payload). The gates enforce the case matrix:
  P1 trojan-shape MUST be HIGH_RISK; N1/N7 MUST be CLEAN (the positive-control gate the CIO owns),
  plus the N2-N6 precision/recall anchors.
"""
from pathlib import Path

import pytest

from hunt.provenance import analyze_repo, CLEAN, SUSPECT, HIGH_RISK

FIX = Path(__file__).resolve().parent / "fixtures" / "provenance"

CASES = {
    "trojan_repo": HIGH_RISK,       # P1 positive control — a+b+c
    "clean_repo": CLEAN,            # N1 legit twin
    "n2_committed_binary": SUSPECT, # committed binary, no lure, not agent-config → a only
    "n3_build_readme": CLEAN,       # legit "run npm build / our CLI" — (b) must NOT fire
    "n4_legit_skills": CLEAN,       # readable skill content — (c) must NOT fire
    "n5_ioc_docs": CLEAN,           # describes IOCs only — must NOT flag a research repo
    "n6_research_sample": SUSPECT,  # IOC docs + benign sample, no lure → capped at SUSPECT
    "n7_readable_hook": CLEAN,      # readable .claude/hooks/*.py — the big FP, must stay CLEAN
    "n8_release_link": CLEAN,       # README links to its own RELEASE asset (.zip) — must NOT fire (b)
    "r1_deceptive_link": HIGH_RISK, # real-world FakeGit shape: benign-anchor links → committed .zip
}


@pytest.mark.parametrize("name,expected", CASES.items())
def test_verdict(name, expected):
    r = analyze_repo(FIX / name)
    assert r["verdict"] == expected, f"{name}: {r['verdict']} != {expected}; fired={r['fired']}"


def test_positive_control_fires_all_three_signals():
    r = analyze_repo(FIX / "trojan_repo")
    assert {"a", "b", "c"} <= set(r["fired"])
    assert r["verdict"] == HIGH_RISK


def test_n7_readable_hook_does_not_trip_agent_config():
    r = analyze_repo(FIX / "n7_readable_hook")
    assert "c" not in r["fired"], "readable honest-extension hook must not fire signal (c)"


def test_n5_research_docs_do_not_trip_any_signal():
    r = analyze_repo(FIX / "n5_ioc_docs")
    assert r["fired"] == [] and r["security_docs_context"] is True


def test_n6_capped_by_security_docs():
    r = analyze_repo(FIX / "n6_research_sample")
    assert r["verdict"] == SUSPECT and r["security_docs_context"] is True


def test_r1_deceptive_link_is_high_via_signal_b():
    # Real-world-derived anchor (FakeGit deceptive-link lure): benign anchor text, href -> committed
    # .zip. Signal (b) must fire on the link shape (no run-verb prose), giving a+b = HIGH_RISK.
    r = analyze_repo(FIX / "r1_deceptive_link")
    assert r["verdict"] == HIGH_RISK and {"a", "b"} <= set(r["fired"])
    assert any("link" in h["why"] for h in r["signals"]["readme_lure"])


def test_n8_release_link_does_not_false_positive():
    # A legit repo linking to its own RELEASE asset (.zip on /releases/, not committed, not /raw/)
    # must NOT trip (b) — the precision guard for the deceptive-link signal.
    r = analyze_repo(FIX / "n8_release_link")
    assert r["verdict"] == CLEAN and r["signals"]["readme_lure"] == []


def test_recall_gaps_are_stated():
    # D2 condition: deferred network signals are logged, never silently capped.
    gaps = " ".join(analyze_repo(FIX / "clean_repo")["recall_gaps"]).lower()
    assert "owner" in gaps and "registry" in gaps
