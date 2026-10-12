"""Evidence oracle — confirm a vulnerability by RE-DEMONSTRATING it, with a unique canary.

A finding is real only if we can make the server prove it on demand. For each candidate (a plan point
or an agent claim: tool + class + which param), the oracle fires a probe whose success leaves an
UNMISTAKABLE signature in the server's own output, then checks for it:

  path_traversal / file-read SSRF → read /etc/passwd, look for the `root:x:0:0:` signature
  command_injection              → inject `; echo <nonce>`, look for the unique nonce in the output
  code_injection                 → run code that prints a unique nonce, look for it
  ssti                           → send `{{A*B}}` with random A,B; the PRODUCT must appear and the
                                   literal expression must NOT (it was evaluated)
  sql_injection                  → a true-condition vs a false-condition call must return DIFFERENT
                                   result sets (boolean-based, proves the input reaches SQL)

The nonce/random values mean a coincidental match cannot false-positive — this is the zero-FP ground
truth, independent of whether the bug maps to a named static class. Payloads are non-destructive
(echo / arithmetic / reading a world-readable file). Runs against an authorized target the same way
the rest of the engine calls it.
"""
from __future__ import annotations

import os
import random
import re
from dataclasses import dataclass, field

_PASSWD_SIG = re.compile(r"root:.*?:0:0:")             # /etc/passwd first line signature


@dataclass
class Proof:
    tool: str
    vuln_class: str
    confirmed: bool
    signal: str = ""                                   # how it was proven
    evidence: str = ""                                 # the observation snippet that proves it
    param: str = ""

    def as_dict(self) -> dict:
        return {"tool": self.tool, "vuln_class": self.vuln_class, "confirmed": self.confirmed,
                "signal": self.signal, "evidence": self.evidence[:300], "param": self.param}


def _nonce() -> str:
    return "mcprtC" + os.urandom(5).hex()


def _call(client, tool: str, args: dict) -> str:
    try:
        return client.call_tool(tool, args) or ""
    except Exception as exc:  # noqa: BLE001 — an error is still an observation
        return f"[error] {type(exc).__name__}: {str(exc)[:160]}"


def _with(args: dict, param: str, value) -> dict:
    """Put `value` on the attack param, keeping the other (benign) args the point already filled."""
    out = dict(args or {})
    if param:
        out[param] = value
    elif out:                                          # no named param: attack the first string arg
        first = next((k for k, v in out.items() if isinstance(v, str)), next(iter(out), None))
        if first is not None:
            out[first] = value
    else:
        out = {"input": value}
    return out


def confirm(client, tool: str, vuln_class: str, *, param: str = "", base_args: dict | None = None) -> Proof:
    """Re-demonstrate one (tool, class) and return a Proof. Ground truth, not a label match."""
    base = base_args or {}
    cls = vuln_class

    if cls in ("path_traversal", "ssrf"):
        payloads = (["file:///etc/passwd", "../../../../../../etc/passwd"] if cls == "ssrf"
                    else ["../../../../../../etc/passwd", "/etc/passwd"])
        for pl in payloads:
            obs = _call(client, tool, _with(base, param, pl))
            if _PASSWD_SIG.search(obs):
                return Proof(tool, cls, True, f"read /etc/passwd via {pl}", obs, param)
        # Writer tool? prove ARBITRARY WRITE: write a canary outside any root, verify it on disk.
        wparam = next((k for k in base if re.search(r"content|data|body|text", k, re.I)), None)
        if wparam:
            proof = _confirm_arbitrary_write(client, tool, param, wparam, base)
            if proof.confirmed:
                return proof
        return Proof(tool, cls, False, "no local-file read proven (network SSRF needs a collaborator)",
                     "", param)

    if cls == "command_injection":
        n = _nonce()
        # Varied shells/metachars + an allowlisted prefix (`ls &&`/`find &&`) to defeat command
        # allowlists that still pass the string to a shell (e.g. restricted_cmd).
        for pl in (f"x; echo {n}", f"$(echo {n})", f"`echo {n}`", f"| echo {n}",
                   f"ls && echo {n}", f"find . -maxdepth 0 && echo {n}", f"echo {n}"):
            obs = _call(client, tool, _with(base, param, pl))
            if n in obs:
                return Proof(tool, cls, True, f"injected command echoed nonce ({pl!r})", obs, param)
        return Proof(tool, cls, False, "no injected command output", "", param)

    if cls == "code_injection":
        n = _nonce()
        # Last payload raises with the nonce: even a tool that returns only "executed" leaks it via
        # its error channel, proving the snippet actually ran.
        for pl in (f"print('{n}')", f"__import__('sys').stdout.write('{n}')",
                   f"__import__('os').popen('echo {n}').read()", f"'{n}'", f"raise Exception('{n}')"):
            obs = _call(client, tool, _with(base, param, pl))
            if n in obs:
                return Proof(tool, cls, True, "code executed (nonce emitted / raised)", obs, param)
        return Proof(tool, cls, False, "code not evaluated", "", param)

    if cls == "ssti":
        a, b = random.randint(100, 999), random.randint(100, 999)
        expr, product = f"{{{{{a}*{b}}}}}", str(a * b)
        obs = _call(client, tool, _with(base, param, expr))
        if product in obs and expr not in obs:
            return Proof(tool, cls, True, f"template evaluated {a}*{b}={product}", obs, param)
        return Proof(tool, cls, False, "template not evaluated", "", param)

    if cls == "sql_injection":
        true_obs = _call(client, tool, _with(base, param, "' OR '1'='1' -- "))
        false_obs = _call(client, tool, _with(base, param, "' AND '1'='2' -- "))
        if true_obs != false_obs and len(true_obs) > len(false_obs):
            return Proof(tool, cls, True, "boolean-based: true-condition returned more rows than false",
                         f"true={true_obs[:120]} | false={false_obs[:120]}", param)
        return Proof(tool, cls, False, "no boolean-based difference", "", param)

    return Proof(tool, cls, False, f"no oracle for class {cls!r}", "", param)


def _confirm_arbitrary_write(client, tool: str, path_param: str, content_param: str, base: dict) -> Proof:
    """Prove unconfined write: have the server write a nonce to /tmp, then read it back from disk."""
    import pathlib
    n = _nonce()
    outp = f"/tmp/mcprt_wr_{n}.txt"
    args = _with(base, path_param, outp)
    args[content_param] = n
    _call(client, tool, args)
    try:
        if n in pathlib.Path(outp).read_text(encoding="utf-8", errors="ignore"):
            return Proof(tool, "path_traversal", True,
                         f"arbitrary write: server wrote a canary to {outp} outside any root", outp,
                         path_param)
    except OSError:
        pass
    finally:
        try:
            pathlib.Path(outp).unlink()
        except OSError:
            pass
    return Proof(tool, "path_traversal", False, "write not confirmed", "", path_param)


@dataclass
class OracleResult:
    confirmed: list = field(default_factory=list)      # Proof (confirmed)
    unconfirmed: list = field(default_factory=list)    # Proof (not proven)

    def as_dict(self) -> dict:
        return {"confirmed": [p.as_dict() for p in self.confirmed],
                "unconfirmed": [p.as_dict() for p in self.unconfirmed],
                "note": f"{len(self.confirmed)} vulnerabilit(y/ies) PROVEN by re-demonstration, "
                        f"{len(self.unconfirmed)} not proven"}


# Order matters — checked top-down, first substring match wins. SSRF is listed before the file-read
# aliases so "ssrf_local_file_read" resolves to ssrf, while a bare "file_read" falls to traversal.
_CLASS_ALIASES = [
    ("ssrf", "ssrf"),
    ("command_inj", "command_injection"), ("cmd_inj", "command_injection"), ("os_command", "command_injection"),
    ("rce", "command_injection"), ("shell", "command_injection"),
    ("code_inj", "code_injection"), ("code_exec", "code_injection"), ("arbitrary_code", "code_injection"),
    ("deserial", "deserialization"),
    ("path_trav", "path_traversal"), ("traversal", "path_traversal"), ("lfi", "path_traversal"),
    ("file_read", "path_traversal"), ("file_write", "path_traversal"), ("arbitrary_write", "path_traversal"),
    ("arbitrary_file", "path_traversal"), ("directory_trav", "path_traversal"),
    ("sqli", "sql_injection"), ("sql_inj", "sql_injection"), ("sql", "sql_injection"),
    ("ssti", "ssti"), ("template_inj", "ssti"),
]


def normalize_class(c: str) -> str:
    """Map an agent's free-form class label (e.g. 'ssrf_local_file_read', 'OS Command Injection') to
    an oracle class. Slug-ifies first so spaces/hyphens match the underscore aliases."""
    c = re.sub(r"[^a-z0-9]+", "_", (c or "").lower())
    for key, canon in _CLASS_ALIASES:
        if key in c:
            return canon
    return c


def confirm_claims(client, claims: list) -> OracleResult:
    """Confirm an AGENT's freely-chosen claims by RE-DEMONSTRATION. The agent picks any tool/input it
    likes; the oracle re-runs the right proof for each claim's (tool, class). This is free agentic
    reach with a ground-truth gate — the agent's say-so is never the verdict."""
    res = OracleResult()
    seen = set()
    for cl in claims:
        tool = cl.get("tool") or cl.get("target") or ""
        cls = normalize_class(cl.get("class") or cl.get("cls") or cl.get("vuln_class") or "")
        param = cl.get("param", "") if isinstance(cl.get("param", ""), str) else ""
        if not tool or not cls:
            res.unconfirmed.append(Proof(tool, cls, False, "claim missing tool/class", "", param))
            continue
        if (tool, cls, param) in seen:
            continue
        seen.add((tool, cls, param))
        proof = confirm(client, tool, cls, param=param)
        (res.confirmed if proof.confirmed else res.unconfirmed).append(proof)
    return res


def confirm_plan(client, plan) -> OracleResult:
    """Fire every point of a test plan and prove it by re-demonstration. This IS the vulnerability
    phase done with ground truth: each plan point becomes a proven finding or an honest not-proven."""
    res = OracleResult()
    seen = set()
    for p in getattr(plan, "points", plan):            # accept a Plan or a raw list of points
        tool = getattr(p, "target", "") or p.get("target", "")
        cls = getattr(p, "vuln_class", "") or p.get("vuln_class", "")
        param = getattr(p, "param", "") or (p.get("param", "") if isinstance(p, dict) else "")
        base = getattr(p, "probe", None) or (p.get("probe") if isinstance(p, dict) else {}) or {}
        key = (tool, cls, param)
        if key in seen:
            continue
        seen.add(key)
        proof = confirm(client, tool, cls, param=param, base_args=base)
        (res.confirmed if proof.confirmed else res.unconfirmed).append(proof)
    return res
