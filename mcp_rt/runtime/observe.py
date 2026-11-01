"""Pure verdict logic for the sealed runtime unit. No network, no subprocess.

Rulings (CIO, design approved):
- Only this run's own token counts as proof. Encoded forms count: hex and base64.
- A token seen in any payload is VULNERABLE and overrides every other row.
- An opaque payload (not inspectable) is never CLEAN: INCONCLUSIVE, or SUSPECTED when a claim
  or unexplained-egress row also applies.
- CLEAN only when every outbound payload was inspectable and none carried the token.
- The vocabularies are generic and frozen before any lab run.
"""
import base64
import re

from hunt.probes import verdict_for
from mcp_rt.runtime.sandbox import _looks_http, has_ipv6_attempt, strace_destinations

# A negative self-claim ("makes no external calls"). Checked against the egress that was observed.
NEGATIVE_CLAIM = re.compile(
    r"\b(?:no|never|without|not|don'?t|doesn'?t|do not|does not)\b[^.;]{0,60}"
    r"\b(?:external|network|internet|outbound|remote|online|telemetry|connections?|requests?|calls?"
    r"|sends?|transmits?|uploads?)\b"
    r"|\b(?:offline|local[- ]only|stays? local|never leaves?)\b", re.I)

# Network purpose words. An outbound attempt is explained only when the declared text carries one of these.
NETWORK_TERM = re.compile(
    r"\b(?:update|updates|upgrade|fetch|fetches|download|downloads|upload|uploads|sync|syncs|remote|http|https"
    r"|url|urls|api|web|online|latest|search|lookup|query|send|sends|webhook|email|weather|proxy|request"
    r"|requests|gateway|cloud|telemetry|notify|notification|dns|network|internet|endpoint|service|services)\b",
    re.I)


# A tool that answers "error: ..." (or similar) refused the benign input it was given, so its sink may not have run.
REFUSAL = re.compile(r"^\s*(?:error|invalid|unknown|not found|unsupported|denied|forbidden|unauthori[sz]ed|refused)\b",
                     re.I)


def _b64_candidates(payload):
    """Every plausible base64 decoding in the payload, at all four character phases and both alphabets."""
    text = payload.decode("latin-1").replace("\r", "").replace("\n", "")
    for run in re.findall(r"[A-Za-z0-9+/_-]{8,}", text):
        for offset in range(4):
            chunk = run[offset:]
            if not chunk:
                continue
            chunk += "=" * (-len(chunk) % 4)  # pad, never truncate: a token can end in the last partial group
            for body in (chunk, chunk.replace("-", "+").replace("_", "/")):
                try:
                    yield base64.b64decode(body)
                except ValueError:
                    continue


def token_hits(payload, token):
    """Which encoded forms of this run's token appear in the payload. Other HT- strings never match."""
    raw = token.encode()
    hits = []
    if raw in payload:
        hits.append("raw")
    if raw.hex().encode() in payload.lower():
        hits.append("hex")
    if any(raw in decoded for decoded in _b64_candidates(payload)):
        hits.append("base64")
    return hits


def inspectable(payload, truncated, port):
    """Could we read this payload in full? If not, it can never clear an attempt."""
    if truncated:
        return False  # only the first CAP bytes were seen; the token could sit past the cut
    if not payload or port == 53:
        return True  # nothing to hide, or plaintext DNS whose names we search
    if payload[0] in (0x14, 0x15, 0x16, 0x17) and len(payload) > 2 and payload[1] == 0x03:
        return False  # a TLS record: encrypted, the token cannot be seen
    head = payload[:512]
    texty = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return texty / len(head) >= 0.9


def _out(method, evidence, **extra):
    return {"verdict": verdict_for(method), "method": method, "evidence": evidence, **extra}


def integrity_problem(sealed, server_started, strace_text, events):
    """An out-dict when the seal/observability is not sound (so no egress verdict can be trusted), else None.
    Shared gate: the agent tier runs it once per sealed session; verdict() runs it per one-shot scan."""
    if not sealed:
        return _out("sandbox_unproven", "sandbox proof failed; server not run")
    if not server_started:
        return _out("sandbox_unproven", "server did not start after the proof; server not run")
    if strace_text is None:
        return _out("sandbox_unobservable", "strace witness missing")
    if has_ipv6_attempt(strace_text):
        return _out("sandbox_unobservable", "IPv6 attempt: the IPv4 recorder cannot capture it")
    if any(e["dst"] is None for e in events):
        return _out("sandbox_unobservable", "recorder could not read an original destination")
    recorded = {(e["dst"], e["port"]) for e in events}
    witnessed = strace_destinations(strace_text)
    if recorded != witnessed:
        return _out("sandbox_unobservable",
                    f"recorder and strace witness disagree: recorder-only {sorted(recorded - witnessed)}, "
                    f"witness-only {sorted(witnessed - recorded)}")
    return None


def classify_egress(events, token, claim_text, refused_calls=()):
    """The egress verdict for a set of recorder events (integrity already established by the caller): a token
    leak is oracle (VULNERABLE, overrides all); an opaque payload is never CLEAN; silence after a refusal is
    not_exercised (never a silent CLEAN); otherwise claim-mismatch / unexplained / opaque / explained.
    Reused per action by the agent tier and per one-shot scan by verdict()."""
    leaks, opaque = [], []
    for e in events:
        payload = base64.b64decode(e["payload"])
        hits = token_hits(payload, token)
        if hits:
            leaks.append((e, hits))
        elif not inspectable(payload, e["truncated"], e["port"]):
            opaque.append(e)
    if leaks:
        e, hits = leaks[0]
        # "oracle" is the existing proof method: a per-run planted marker fired. Our token is exactly that.
        return _out("oracle",
                    f"planted test value observed leaving: {e['proto']} to {e['dst']}:{e['port']} ({'/'.join(hits)} form)",
                    attempts=len(events))
    if not events:
        if refused_calls:
            # Silence after a refusal proves nothing: the sink may never have been reached. Never a silent CLEAN.
            return _out("sandbox_not_exercised",
                        f"no outbound attempt, but {', '.join(sorted(set(refused_calls)))} refused the benign input; "
                        "its sink may not have run")
        return _out("sandbox_no_egress", "no outbound attempt observed")
    where = ", ".join(sorted({f"{e['proto']} {e['dst']}:{e['port']}" for e in events}))
    note = f"; {len(opaque)} payload(s) not inspectable" if opaque else ""
    claim = NEGATIVE_CLAIM.search(claim_text)
    if claim:
        return _out("sandbox_claim_mismatch", f'says "{claim.group(0)[:60]}" but sent {where}{note}')
    if not NETWORK_TERM.search(claim_text):
        return _out("sandbox_unexplained_egress", f"sent {where}; no network purpose in its declared text{note}")
    if opaque:
        return _out("sandbox_opaque_payload", f"sent {where}, which fits its purpose, but the payload is not inspectable")
    return _out("sandbox_explained_egress", f"sent {where}; payloads inspected, no test value, fits its declared purpose")


def verdict(*, sealed, server_started, events, strace_text, token, claim_text, refused_calls=()):
    """events: the server-phase recorder records. strace_text: witness output, or None if it is missing."""
    problem = integrity_problem(sealed, server_started, strace_text, events)
    return problem if problem is not None else classify_egress(events, token, claim_text, refused_calls)


def classify_redirect_follow(events, *, sentinel_port, canary_port, nonce):
    """#28 upstream-redirect SSRF oracle. The sealed recorder answered the server's request to its CONFIGURED
    upstream (sentinel_port) with a 302 to an INTERNAL canary (canary_port, path=<nonce>). Did the server
    FOLLOW the redirect to the internal destination?
      follows (requests the canary carrying our nonce)            -> VULNERABLE (oracle)
      called the upstream, got the 302, did NOT request the canary -> CLEAN (oracle_negative; revalidated)
      never called the upstream, OR used TLS we cannot 302         -> INCONCLUSIVE (redirect_not_confirmed)
    Integrity (seal proven, recorder vs strace) is established by the caller, exactly like classify_egress."""
    nonce_b = nonce.encode()
    for e in events:
        if e["proto"] == "tcp" and e["port"] == canary_port and nonce_b in base64.b64decode(e["payload"]):
            return _out("oracle",
                        f"server followed the upstream's 302 to the internal canary 127.0.0.1:{canary_port} "
                        f"(nonce {nonce}) — redirect-follow SSRF", attempts=len(events))
    sentinel = [e for e in events if e["proto"] == "tcp" and e["port"] == sentinel_port]
    if not sentinel:
        return _out("redirect_not_confirmed",
                    f"the server never requested the configured upstream (sentinel 127.0.0.1:{sentinel_port}); "
                    "the oracle was not exercised")
    if any(_looks_http(base64.b64decode(e["payload"])) for e in sentinel):
        return _out("oracle_negative",
                    "server requested the upstream and received a 302 to the internal canary but did NOT "
                    "follow it — revalidated/blocked the internal destination")
    return _out("redirect_not_confirmed",
                "the server's upstream request was not plaintext HTTP (TLS we cannot terminate to emit the "
                "302); the redirect-follow is unobservable under the seal — INCONCLUSIVE, not CLEAN")
