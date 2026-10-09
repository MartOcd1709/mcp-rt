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


# ---- deep tier -------------------------------------------------------------------------
_DEEP_CLEAN = {
    "base": _REPORT,
    "mcp_cap": {"status": "OK", "findings": []},
    "agent_redteam": {"status": "INCONCLUSIVE", "findings": []},
    "components": {"direct_probe": "ran", "mcp_cap": "ran", "agent_redteam": "skipped: inconclusive"},
}


def test_deep_claim_records_tier_and_components():
    claim = attest.build_claim(_REPORT, tier="deep", deep=_DEEP_CLEAN)
    assert claim["scan"]["tier"] == "deep"
    assert claim["scan"]["components"]["mcp_cap"] == "ran"
    assert claim["scan"]["verdict"] == "CLEAN"   # base CLEAN, no deep findings


def test_deep_mcp_cap_finding_forces_vulnerable():
    deep = {**_DEEP_CLEAN,
            "mcp_cap": {"status": "OK", "findings": [{"tool": "x", "observation": "opened /etc/shadow"}]}}
    claim = attest.build_claim(_REPORT, tier="deep", deep=deep)   # base CLEAN but MCP-00 fired
    assert claim["scan"]["verdict"] == "VULNERABLE"
    assert claim["finding_summary"]["mcp_cap_undeclared"] == 1


def test_deep_evidence_digests_the_full_bundle():
    # evidence_sha256 must bind base+deep, not just base: changing a deep finding must break it.
    claim = attest.build_claim(_REPORT, tier="deep", deep=_DEEP_CLEAN)
    assert attest.verify_evidence(claim_env(claim), attest.evidence_object(_REPORT, _DEEP_CLEAN)) is True
    mutated = {**_DEEP_CLEAN, "mcp_cap": {"status": "OK", "findings": [{"tool": "y", "observation": "z"}]}}
    assert attest.verify_evidence(claim_env(claim), attest.evidence_object(_REPORT, mutated)) is False


def claim_env(claim):   # helper: wrap a claim so verify_evidence can read evidence_sha256
    return {"claim": claim}
