"""Verifiable ground-truth attestation: sign -> offline-verify -> tamper fails.

The moat's core guarantee: a second party, with ONLY the attestation file, can verify the
signature (no call back to us); editing any claim field breaks it; the badge and claim never
carry raw finding bodies (no pre-disclosure leak).
"""
from mcp_rt import attest

_REPORT = {
    "target": "npx -y some-mcp-server",
    "scanned_at": "2026-10-08T12:00:00",
    "verdict": "CLEAN",
    "findings": [],
    "coverage": [{"tool": "t", "cls": "command_injection", "verdict": "CLEAN"},
                 {"tool": "t", "cls": "path_traversal", "verdict": "CLEAN"}],
}


def _sign(report=_REPORT):
    key = attest.load_or_create_key  # noqa: F841  (ensure importable)
    k = attest.ed25519.Ed25519PrivateKey.generate()
    return attest.sign(attest.build_claim(report, mcp_rt_version="9.9.9"), k)


def test_sign_then_verify_offline():
    ok, reason = attest.verify(_sign())
    assert ok, reason


def test_tampering_any_field_breaks_verification():
    env = _sign()
    env["claim"]["scan"]["verdict"] = "VULNERABLE"      # flip the verdict post-signing
    ok, _ = attest.verify(env)
    assert ok is False


def test_wrong_key_fails():
    env = _sign()
    other = attest.ed25519.Ed25519PrivateKey.generate()
    env["sig"]["public_key"] = attest.public_key_hex(other)   # claim signer isn't the real one
    assert attest.verify(env)[0] is False


def test_evidence_digest_binds_the_report():
    env = _sign()
    assert attest.verify_evidence(env, _REPORT) is True
    assert attest.verify_evidence(env, {**_REPORT, "verdict": "VULNERABLE"}) is False


def test_claim_carries_no_raw_findings():
    # VULNERABLE report with a sensitive finding body -> claim has counts, not the body.
    rep = {**_REPORT, "verdict": "VULNERABLE",
           "findings": [{"sev": "Critical", "cls": "command_injection",
                         "evidence": "SECRET_POC_payload=rm -rf"}]}
    claim = attest.build_claim(rep)
    blob = attest.canonical_bytes(claim).decode()
    assert "SECRET_POC_payload" not in blob
    assert claim["finding_summary"] == {"Critical": 1}


def test_badge_reflects_verdict_color():
    assert "#2e9e3f" in attest.make_badge(_sign())                       # CLEAN -> green
    bad = _sign({**_REPORT, "verdict": "VULNERABLE", "findings": [{"sev": "High"}]})
    assert "#c62828" in attest.make_badge(bad)                           # VULNERABLE -> red


def test_keypair_roundtrip_persists(tmp_path):
    p = tmp_path / "k.pem"
    k1 = attest.load_or_create_key(p)
    k2 = attest.load_or_create_key(p)      # second call loads the same key
    assert attest.public_key_hex(k1) == attest.public_key_hex(k2)
