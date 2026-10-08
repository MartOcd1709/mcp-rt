"""Remote / hosted MCP server scanning — AUTHORIZED engagements only.

CONSENT-GATED: refuses to run without an explicit ``--authorized-by`` attestation, and
records it with every result. Scanning a hosted service you are not authorized to test is
prohibited; this module exists for client engagements (the client hands you their URL +
written authorization), not for scanning arbitrary internet servers.

For a hosted server we connect over the agent<->server channel (streamable-http, SSE
fallback) and run the probes that verdict from the RESPONSE or advertised METADATA —
`tool_poisoning`, `sql_injection`, `ssti`, `rug_pull` — which work transport-agnostically.
The sink/canary probes (`ssrf`, `command_injection`, `path_traversal`) need an out-of-band
sink the remote host can reach back to; they are reported NOT RUN here (a public-collaborator
backend is future work). Credential-exfil stays **UNOBSERVABLE_BY_DESIGN**: we cannot see the
remote server's own backend egress — stated honestly, never faked.

    mcp-rt remote --url https://mcp.example.com/mcp \\
                  --authorized-by "Jane Doe, Acme Corp — authorization ticket ACME-42"
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import re
import sys
from pathlib import Path

from mcp import ClientSession

from hunt.probes import VULNERABLE, probe_rug_pull, probe_sql_injection, probe_ssti, probe_tool_poisoning

# Probes safe/meaningful over a remote channel (verdict from response or advertised metadata).
_REMOTE_PROBES = [probe_tool_poisoning, probe_sql_injection, probe_ssti, probe_rug_pull]
# Need a local/collaborator sink the remote host reaches back to — not run remotely here.
_SINK_PROBES = ["ssrf", "command_injection", "path_traversal"]


async def _connect_and_run(url: str, headers: dict):
    """Connect over streamable-http (SSE fallback), enumerate tools, run the remote probes."""
    last = None
    for transport in ("streamable", "sse"):
        try:
            if transport == "streamable":
                from mcp.client.streamable_http import streamablehttp_client
                cm = streamablehttp_client(url, headers=headers)
            else:
                from mcp.client.sse import sse_client
                cm = sse_client(url, headers=headers)
            async with cm as streams:
                read, write = streams[0], streams[1]
                async with ClientSession(read, write) as s:
                    await s.initialize()
                    tools = (await s.list_tools()).tools
                    results = []
                    for probe in _REMOTE_PROBES:
                        results.extend(await probe(s, tools))
                    return {"transport": transport, "tools": [t.name for t in tools], "results": results}
        except Exception as exc:  # noqa: BLE001
            last = f"{transport}: {type(exc).__name__}: {str(exc)[:120]}"
    return {"error": last or "could not connect"}


async def check_origin_validation(url: str, base_headers: dict) -> tuple[str, str]:
    """DNS-rebinding test: does the server accept a request with a FOREIGN Origin?

    Raw HTTP probe (reads the status directly, unlike the MCP client which wraps a 403 in a
    TaskGroup). A security rejection (403/421) = Origin validated = CLEAN. Any response that
    reaches the app (2xx, or a 400/406 protocol error) = the foreign Origin was NOT blocked =
    VULNERABLE (the CVE-2025-66416 / CVE-2026-35568 class). Low-intrusiveness: one initialize.
    """
    import urllib.error
    import urllib.request

    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "mcp-rt", "version": "0"}}}).encode()
    headers = {**base_headers, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream", "Origin": "http://attacker.evil"}
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=8)
        return ("VULNERABLE", f"foreign Origin accepted (HTTP {resp.status}) — no Origin validation "
                              f"(DNS-rebinding risk)")
    except urllib.error.HTTPError as e:
        if e.code in (403, 421):
            return ("CLEAN", f"foreign Origin rejected (HTTP {e.code}) — server validates Origin")
        return ("VULNERABLE", f"foreign Origin not blocked (HTTP {e.code}, app-level error) — "
                              f"no Origin validation (DNS-rebinding risk)")
    except Exception as exc:  # noqa: BLE001
        return ("INCONCLUSIVE", f"could not reach/parse endpoint: {str(exc)[:120]}")


# Header names that gate access — stripped for the no-auth probe; routing headers (X-Tenant) are kept.
_AUTH_HDR = re.compile(r"authorization|api[-_]?key|x[-_]?auth|auth[-_]?token|^token$|cookie", re.I)


def _auth_headers(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if _AUTH_HDR.search(k)}


def _unauth_finding(auth_present: bool, unauth_ok: bool) -> dict | None:
    """A credential-free session is a VULN only when auth WAS supplied yet stripping it still
    connected. An open server with no credentials supplied is by-design open — never a finding."""
    if auth_present and unauth_ok:
        return {"cls": "missing_auth", "tool": "(transport)",
                "evidence": "initialize + tools/list succeeded with auth headers stripped",
                "detail": "server accepts UNAUTHENTICATED sessions despite auth being supplied — "
                          "authentication not enforced (CWE-287, CVE-2025-66414 class)"}
    return None


async def check_unauthenticated(url: str, headers: dict | None = None) -> bool:
    """Active test: does a session initialize + list tools with the AUTH headers stripped
    (non-auth headers kept)? Interpret via _unauth_finding — only a bypass if auth was supplied."""
    noauth = {k: v for k, v in (headers or {}).items() if not _AUTH_HDR.search(k)}
    for transport in ("streamable", "sse"):
        try:
            if transport == "streamable":
                from mcp.client.streamable_http import streamablehttp_client
                cm = streamablehttp_client(url, headers=noauth)
            else:
                from mcp.client.sse import sse_client
                cm = sse_client(url, headers=noauth)
            async with cm as streams:
                async with ClientSession(streams[0], streams[1]) as s:
                    await s.initialize()
                    await s.list_tools()
                    return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _oauth_findings(meta: dict, dcr_open) -> list[dict]:
    """Pure: evaluate OAuth authorization-server metadata (+ a confirmed DCR result) for weaknesses."""
    out = []
    methods = meta.get("code_challenge_methods_supported") or []
    if "S256" not in methods:
        out.append({"cls": "oauth_pkce", "tool": "(oauth)",
                    "evidence": f"code_challenge_methods_supported={methods or 'absent'}",
                    "detail": "authorization server does not advertise PKCE S256 — authorization-code "
                              "interception/injection risk for public clients (CWE-287)"})
    if dcr_open is True:
        out.append({"cls": "oauth_open_dcr", "tool": "(oauth)",
                    "evidence": "unauthenticated POST to registration_endpoint returned a client_id",
                    "detail": "open dynamic client registration — any party can register an OAuth client "
                              "without authorization (confused-deputy / token-theft surface, CWE-287)"})
    return out


def _fetch_oauth_meta(url: str):
    """Fetch the OAuth authorization-server metadata for the endpoint's origin; None if there's no OAuth AS."""
    import urllib.parse
    import urllib.request
    o = urllib.parse.urlsplit(url)
    origin = f"{o.scheme}://{o.netloc}"
    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        try:
            return json.load(urllib.request.urlopen(origin + path, timeout=8))
        except Exception:  # noqa: BLE001
            continue
    return None


def _try_unauth_dcr(reg_endpoint: str):
    """One SYNTHETIC unauthenticated client registration (RFC 7591) to CONFIRM open DCR.
    True = accepted (open), False = rejected/auth-required (protected), None = couldn't tell."""
    import urllib.error
    import urllib.request
    body = json.dumps({"client_name": "mcprt-oauth-probe",
                       "redirect_uris": ["https://mcprt-oauth-probe.example/cb"]}).encode()
    req = urllib.request.Request(reg_endpoint, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        return bool(json.load(urllib.request.urlopen(req, timeout=8)).get("client_id"))
    except urllib.error.HTTPError as e:
        return False if e.code in (401, 403) else None     # auth required = protected (good)
    except Exception:  # noqa: BLE001
        return None


async def check_oauth_metadata(url: str) -> tuple[str, list[dict]]:
    """OAuth posture: PKCE support (metadata) + a GROUND-TRUTHED open-DCR test (one synthetic
    registration). NOT_APPLICABLE when the server exposes no OAuth authorization-server metadata."""
    meta = _fetch_oauth_meta(url)
    if meta is None:
        return ("NOT_APPLICABLE", [])
    dcr_open = _try_unauth_dcr(meta["registration_endpoint"]) if meta.get("registration_endpoint") else None
    findings = _oauth_findings(meta, dcr_open)
    return ("VULNERABLE" if findings else "CLEAN", findings)


def scan_remote(url: str, headers: dict, authorized_by: str) -> dict:
    run = asyncio.run(_connect_and_run(url, headers))
    origin_verdict, origin_detail = asyncio.run(check_origin_validation(url, headers))
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    base = {"target": url, "mode": "remote", "scanned_at": ts, "authorized_by": authorized_by,
            "unobservable": ("Credential-exfil is UNOBSERVABLE_BY_DESIGN for a remote server: "
                             "its backend egress is not visible from the client side."),
            "not_run": {p: "needs an out-of-band collaborator sink the remote host can reach" for p in _SINK_PROBES}}
    if "error" in run:
        return {**base, "verdict": "INCONCLUSIVE", "note": run["error"], "findings": []}
    findings = [{"cls": r.probe, "tool": r.tool, "evidence": r.evidence, "detail": r.rationale}
                for r in run["results"] if r.verdict == VULNERABLE]
    if origin_verdict == "VULNERABLE":
        findings.append({"cls": "dns_rebinding", "tool": "(transport)",
                         "evidence": "foreign Origin/Host accepted", "detail": origin_detail})
    auth_present = bool(_auth_headers(headers))
    unauth = asyncio.run(check_unauthenticated(url, headers))   # active probe (auth stripped), not a guess
    if af := _unauth_finding(auth_present, unauth):
        findings.append(af)                                     # auth supplied but not enforced
    oauth_verdict, oauth_findings = asyncio.run(check_oauth_metadata(url))   # OAuth AS posture + DCR
    findings += oauth_findings
    return {**base, "transport": run["transport"], "tools": run["tools"],
            "verdict": "VULNERABLE" if findings else "CLEAN", "findings": findings,
            "origin_validation": origin_verdict, "auth_supplied": auth_present,
            "unauthenticated_session": unauth, "oauth": oauth_verdict}


def _preserve(rep: dict) -> str:
    logs = Path(__file__).resolve().parent / "logs"
    logs.mkdir(exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in rep["target"])[:50] or "remote"
    path = logs / f"{stamp}_remote_{safe}.json"
    path.write_text(json.dumps(rep, indent=2, default=str))
    return str(path)


def _record(rep: dict, log_path: str) -> None:
    from hunt.findings_db import DB
    db = DB()
    tid = db.add_target(name=rep["target"], install_cmd=f"REMOTE {rep['target']}", source="remote")
    note_auth = f"[AUTHORIZED-BY: {rep['authorized_by']}] "
    if rep["verdict"] == "INCONCLUSIVE":
        db.add_scan(tid, mode="remote", verdict="INCONCLUSIVE", evidence=log_path,
                    notes=note_auth + rep.get("note", ""))
    elif rep["findings"]:
        for f in rep["findings"]:
            db.add_scan(tid, mode=f"remote:{f['cls']}", verdict=VULNERABLE, evidence=log_path,
                        notes=note_auth + f"{f['tool']}: {f['detail']}"[:400])
    else:
        db.add_scan(tid, mode="remote", verdict="CLEAN", evidence=log_path,
                    notes=note_auth + "no findings via remote response/metadata probes")
    db.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt remote", description="authorized remote MCP server scan")
    p.add_argument("--url", required=True, help="the hosted MCP server endpoint (https://.../mcp)")
    p.add_argument("--authorized-by", default="",
                   help="REQUIRED attestation: who authorized this scan + reference (name, org, ticket)")
    p.add_argument("--header", action="append", default=[], metavar="'K: V'",
                   help="auth/other header for the connection (repeatable)")
    args = p.parse_args(argv)

    if not args.authorized_by.strip():
        print("REFUSED: remote scanning requires explicit authorization.\n"
              "  Re-run with --authorized-by \"<name, org, authorization reference>\".\n"
              "  Scanning a hosted MCP server you are not authorized to test is prohibited and\n"
              "  would undermine the responsible-disclosure credibility this tool depends on.")
        return 2

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    rep = scan_remote(args.url, headers, args.authorized_by.strip())
    log_path = _preserve(rep)
    _record(rep, log_path)

    print(f"remote scan: {rep['target']}  ->  {rep['verdict']}")
    print(f"  authorized-by: {rep['authorized_by']}")
    if rep["verdict"] == "INCONCLUSIVE":
        print(f"  could not connect: {rep.get('note')}")
    else:
        print(f"  transport: {rep.get('transport')}  tools: {len(rep.get('tools', []))}")
        for f in rep["findings"]:
            print(f"    [VULN] {f['cls']:16} {f['tool']}: {f['detail']}")
        if rep.get("unauthenticated_session") and not rep.get("auth_supplied"):
            print("    [info] accepts credential-free sessions, but no auth header was supplied to "
                  "compare — open server (by-design unless it should require auth)")
        if not rep["findings"]:
            print("    no findings via remote probes")
    print(f"  {rep['unobservable']}")
    print(f"  not run remotely (need out-of-band sink): {', '.join(_SINK_PROBES)}")
    print(f"  report: {log_path}")
    return 1 if rep["verdict"] == "VULNERABLE" else 0


if __name__ == "__main__":
    sys.exit(main())
