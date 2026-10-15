"""T2 / SAM1-13 — MRTR requestState tamper + replay + cross-user probe (oracle-gated).

A MALICIOUS MCP client (spec says a conformant client MUST NOT inspect/modify `requestState`; we do,
to test the server). Ground truth only: a sub-case FIRES iff the server returns the planted CANARY
(tamper / cross-user) or redeems a consumed voucher a second time (replay), AND the probe's unique
per-run nonce is echoed — so a hit can't be coincidence. No model judgement anywhere.

Verdict per sub-case: {"case", "fired": bool, "evidence": str}. Benign also carries "completed".
"""
from __future__ import annotations

import base64
import json
import secrets

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026
from tests.fixtures.mrtr_requeststate_hosts import CANARY

_INPUT = {"confirm": {"action": "decline"}}   # a valid InputResponses map keyed to the server's request


def _params(nonce: str) -> dict:
    # the retry re-sends the ORIGINAL request params (name + arguments) plus inputResponses/requestState
    return {"name": "redeem", "arguments": {"nonce": nonce}}


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _retarget(request_state: str, new_grant: str) -> str:
    """Tamper: decode the opaque blob, repoint `grant`, re-encode — leaving any integrity tag intact
    (so it no longer verifies). A server that honors this failed spec #4."""
    seg = request_state.split(".")
    payload = json.loads(_b64d(seg[0]))
    payload["grant"] = new_grant
    seg[0] = _b64e(json.dumps(payload).encode())
    return ".".join(seg)


def _auth(principal: str) -> dict:
    return {"Authorization": f"Bearer {principal}"}


def _resume_text(client, *, params, request_state, headers):
    """Resume and return response text, or None if the server REJECTED (any non-2xx / transport error)."""
    try:
        res = client.resume("tools/call", params, request_state=request_state,
                            input_responses=_INPUT, extra_headers=headers)
        return _result_text_2026(res)
    except Exception:  # noqa: BLE001 — a rejection (HTTP 400) is the resilient outcome, not a crash
        return None


def _nonce() -> str:
    return "n-" + secrets.token_hex(8)


def probe_tamper(url: str) -> dict:
    nonce = _nonce()
    params = _params(nonce)
    c = StatelessHTTPClient(url)
    begin = c.begin("tools/call", params, extra_headers=_auth("attacker"))
    tampered = _retarget(begin["requestState"], "victim")      # attacker repoints the grant to the victim
    text = _resume_text(c, params=params, request_state=tampered, headers=_auth("attacker"))
    fired = bool(text) and CANARY in text and nonce in text
    return {"case": "tamper", "fired": fired, "evidence": (text or "REJECTED")[:120]}


def probe_cross_user(url: str) -> dict:
    nonce = _nonce()
    params = _params(nonce)
    c = StatelessHTTPClient(url)
    # attacker obtains a requestState minted for principal "victim" (models interception), then presents
    # it under the attacker's own authenticated principal.
    vstate = c.begin("tools/call", params, extra_headers=_auth("victim"))["requestState"]
    text = _resume_text(c, params=params, request_state=vstate, headers=_auth("attacker"))
    fired = bool(text) and CANARY in text and nonce in text
    return {"case": "cross_user", "fired": fired, "evidence": (text or "REJECTED")[:120]}


def probe_replay(url: str) -> dict:
    nonce = _nonce()
    params = _params(nonce)
    c = StatelessHTTPClient(url)
    state = c.begin("tools/call", params, extra_headers=_auth("attacker"))["requestState"]
    first = _resume_text(c, params=params, request_state=state, headers=_auth("attacker"))   # legit one-time redemption
    second = _resume_text(c, params=params, request_state=state, headers=_auth("attacker"))  # REPLAY of consumed state
    # fire = the one-time operation demonstrably ran a SECOND time (REDEEMED#2) with our nonce
    fired = bool(second) and "REDEEMED#2" in second and nonce in second
    return {"case": "replay", "fired": fired, "evidence": f"first={first!r} second={(second or 'REJECTED')!r}"[:160]}


def probe_benign(url: str) -> dict:
    """Control (d): a conformant retry — echo the state unchanged, same principal. MUST complete and
    MUST NOT surface the canary. Proves the probe doesn't false-positive and that a resilient host is
    resilient for the RIGHT reason (it still completes legitimate work)."""
    nonce = _nonce()
    params = _params(nonce)
    c = StatelessHTTPClient(url)
    state = c.begin("tools/call", params, extra_headers=_auth("attacker"))["requestState"]
    text = _resume_text(c, params=params, request_state=state, headers=_auth("attacker"))
    completed = bool(text) and "REDEEMED#1" in text and nonce in text and CANARY not in text
    return {"case": "benign", "fired": False, "completed": completed, "evidence": (text or "REJECTED")[:120]}


def assess(url: str) -> list[dict]:
    """Run all four sub-cases against one host. VULNERABLE iff any attack sub-case fired."""
    return [probe_tamper(url), probe_replay(url), probe_cross_user(url), probe_benign(url)]
