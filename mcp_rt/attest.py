"""Verifiable ground-truth attestation — mcp-rt's moat.

The funded field (Snyk, AgentAvow, the official MCP registry) signs *static opinions* or
admits it doesn't certify security at all. mcp-rt signs *proof*: a real scan ran against
*this* server, and here is a signed, offline-verifiable record of the verdict and the
evidence digest. Anyone can verify the signature with only the embedded public key — no
call back to us, nothing trusted but the math.

Privacy stance (the hard Snyk contrast): building and signing an attestation is fully local
— nothing in here phones home. Publishing it anywhere is the operator's separate, explicit act.

Artifact shape
--------------
A signed attestation is an envelope::

    {"claim": {...}, "sig": {"alg": "ed25519", "public_key": "<hex>", "signature": "<hex>"}}

``signature`` is Ed25519 over ``canonical_bytes(claim)`` (RFC-8785-ish: sorted keys, no
whitespace). Tampering with any claim field breaks verification. The claim carries the
verdict, what was tested, and a digest of the full report — not the raw findings, so the
badge/registry never leaks a vuln's specifics before coordinated disclosure.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

SCHEMA = "mcp-rt/attestation/v1"
_DEFAULT_KEY = Path.home() / ".mcp-rt" / "attest_key.pem"


def canonical_bytes(obj: dict) -> bytes:
    """Deterministic JSON bytes for signing/digesting: sorted keys, no insignificant space."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(obj: dict) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def build_claim(report: dict, *, client: str = "n/a", capture: str = "n/a",
                mcp_rt_version: str = "", artifact_sha256: str = "") -> dict:
    """Build the signable claim from a run_full_scan/scan report.

    Carries verdict + what-was-tested + a digest of the full report (evidence_sha256), plus a
    severity-count summary — never the raw finding bodies, so a signed/badged attestation can't
    leak a vulnerability's specifics ahead of disclosure. The full report stays beside it.
    """
    findings = report.get("findings", []) or []
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("sev", "") if isinstance(f, dict) else ""
        if sev:
            counts[sev] = counts.get(sev, 0) + 1
    classes = sorted({c.get("cls", "") for c in (report.get("coverage", []) or []) if c.get("cls")})
    return {
        "schema": SCHEMA,
        "target": {"spec": report.get("target", ""), "artifact_sha256": artifact_sha256},
        "scan": {
            "verdict": report.get("verdict", ""),
            "classes_tested": classes,
            "client": client,
            "capture": capture,
            "mcp_rt_version": mcp_rt_version,
        },
        "finding_summary": counts,
        "evidence_sha256": _sha256(report),
        "scanned_at": report.get("scanned_at", ""),
        "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }


# --------------------------------------------------------------------------------------
# Keypair — self-signed Ed25519 (transparency-log upgrade is a later, additive step).
# --------------------------------------------------------------------------------------
def load_or_create_key(path: Path | str = _DEFAULT_KEY) -> ed25519.Ed25519PrivateKey:
    """Load the operator's signing key, creating one (0600) on first use. Fully local."""
    path = Path(path)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = ed25519.Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    path.chmod(0o600)
    return key


def public_key_hex(key: ed25519.Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


# --------------------------------------------------------------------------------------
# Sign / verify
# --------------------------------------------------------------------------------------
def sign(claim: dict, key: ed25519.Ed25519PrivateKey) -> dict:
    """Return a signed envelope {claim, sig} — Ed25519 over the canonical claim bytes."""
    sig = key.sign(canonical_bytes(claim)).hex()
    return {"claim": claim, "sig": {"alg": "ed25519", "public_key": public_key_hex(key), "signature": sig}}


def verify(envelope: dict) -> tuple[bool, str]:
    """Offline-verify a signed attestation. Returns (ok, reason). Needs only the envelope.

    Checks the Ed25519 signature over the canonical claim with the embedded public key — so any
    edit to any claim field (verdict, target, evidence digest…) flips it to invalid.
    """
    try:
        claim, sig = envelope["claim"], envelope["sig"]
        if sig.get("alg") != "ed25519":
            return False, f"unsupported alg {sig.get('alg')!r}"
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"]))
        pub.verify(bytes.fromhex(sig["signature"]), canonical_bytes(claim))
        return True, "signature valid"
    except InvalidSignature:
        return False, "signature does NOT match claim (tampered or wrong key)"
    except (KeyError, ValueError) as exc:
        return False, f"malformed attestation: {exc}"


def verify_evidence(envelope: dict, report: dict) -> bool:
    """True if ``report`` is exactly the evidence this attestation was issued over."""
    return envelope.get("claim", {}).get("evidence_sha256") == _sha256(report)


# --------------------------------------------------------------------------------------
# Badge — embeddable SVG linking to the verify permalink.
# --------------------------------------------------------------------------------------
_BADGE_COLORS = {"CLEAN": "#2e9e3f", "VULNERABLE": "#c62828", "SETUP_FAILED": "#8a8a8a"}


def make_badge(envelope: dict) -> str:
    """A shields-style SVG: 'mcp-rt | <VERDICT>'. Color by verdict; neutral if unknown."""
    claim = envelope.get("claim", {})
    verdict = (claim.get("scan", {}) or {}).get("verdict", "UNKNOWN") or "UNKNOWN"
    color = _BADGE_COLORS.get(verdict, "#8a8a8a")
    left, right = "mcp-rt", verdict
    lw, rw = 52, max(58, 8 * len(right) + 16)   # rough text widths
    w = lw + rw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" '
        f'aria-label="mcp-rt: {right}">'
        f'<rect width="{lw}" height="20" fill="#444"/>'
        f'<rect x="{lw}" width="{rw}" height="20" fill="{color}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw/2:.0f}" y="14" text-anchor="middle">{left}</text>'
        f'<text x="{lw + rw/2:.0f}" y="14" text-anchor="middle">{right}</text>'
        f'</g></svg>'
    )
