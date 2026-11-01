"""T10.5 / SAM1-21 — forced downgrade-to-deprecated probe (oracle-gated).

Serving the legacy protocolVersion during the 12-month overlap is PERMITTED — so this is NOT a MUST-
violation. The defect is a downgrade-bypass: a security control (profile redaction) applied on the
modern path but NOT uniformly on the deprecated path. The probe FORCES the old version via the client's
protocol_version param (T1 only RECORDS downgrade-availability; T10.5 forces + proves impact). Ground
truth: FIRES iff the forced-legacy path returns the per-run profile CANARY while the modern path on the
SAME host is clean.
"""
from __future__ import annotations

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026

PV_MODERN = "2026-07-28"
PV_LEGACY = "2025-06-18"


def _canary(tok: str) -> str:
    return f"PROFILE-SECRET-{tok}"


def _profile(url: str, version: str) -> str:
    c = StatelessHTTPClient(url, protocol_version=version)
    return _result_text_2026(c.begin("tools/call", {"name": "read_profile", "arguments": {}}))


def probe_forced_downgrade(url: str, tok: str) -> dict:
    text = _profile(url, PV_LEGACY)                          # FORCE the deprecated version
    fired = _canary(tok) in text
    return {"case": "forced_downgrade", "fired": fired, "evidence": text[:120]}


def probe_modern(url: str, tok: str) -> dict:
    """Same tool on the modern path. On VulnerableHost this is the killer control (must be CLEAN, so the
    canary in (a) is caused by the downgrade, not a tool that always leaks). On SafeHost it's the benign
    control (must complete)."""
    text = _profile(url, PV_MODERN)
    clean = _canary(tok) not in text
    completes = "public fields" in text
    return {"case": "modern", "fired": _canary(tok) in text, "clean": clean, "completes": completes,
            "evidence": text[:120]}
