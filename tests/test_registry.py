"""Static attestation registry: lists attestations, verifies each at build time.

A valid attestation is marked valid; a tampered one is marked INVALID rather than listed as
trustworthy. Permalinks point at verify.html?att=<file> so each row re-verifies in the browser.
"""
import json

from mcp_rt import attest
from hunt import registry


def _write_att(dir_, name, verdict):
    key = attest.ed25519.Ed25519PrivateKey.generate()
    rep = {"target": name, "scanned_at": "2026-10-09T00:00:00", "verdict": verdict,
           "findings": [] if verdict == "CLEAN" else [{"sev": "High"}],
           "coverage": [{"cls": "sql_injection", "verdict": verdict}]}
    env = attest.sign(attest.build_claim(rep, mcp_rt_version="1.0"), key)
    (dir_ / f"{name}.attestation.json").write_text(json.dumps(env), encoding="utf-8")
    return env


def test_registry_lists_and_verifies(tmp_path):
    _write_att(tmp_path, "good-server", "CLEAN")
    out = registry.build(tmp_path, "Test Registry")
    htmltext = out.read_text()
    assert "good-server" in htmltext
    assert "verify.html?att=good-server.attestation.json" in htmltext
    assert "✓ valid" in htmltext
    assert (tmp_path / "verify.html").exists()        # permalinks must resolve


def test_registry_flags_tampered(tmp_path):
    env = _write_att(tmp_path, "tampered", "VULNERABLE")
    env["claim"]["scan"]["verdict"] = "CLEAN"          # forge CLEAN after signing
    (tmp_path / "tampered.attestation.json").write_text(json.dumps(env), encoding="utf-8")
    htmltext = registry.build(tmp_path, "T").read_text()
    assert "INVALID" in htmltext


def test_empty_registry_renders(tmp_path):
    htmltext = registry.build(tmp_path, "Empty").read_text()
    assert "No attestations" in htmltext
