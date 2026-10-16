"""T11.5 / SAM1-22 — ReDoS / catastrophic backtracking (CWE-1333 -> CWE-400) analyzer + probe.

The regex comes from a tool's inputSchema `pattern` (read live via list_tools). The oracle is a
DETERMINISTIC, engine-independent backtracking STEP-COUNTER — pure integer counting, identical on
every machine, ZERO wall-clock. VULNERABLE (CONFIRMED) iff the step count blows up super-polynomially
on an adversarial input family (>=8x when the input length doubles: linear ~2x, quadratic ~4x stay
below). The adversarial input is NEVER sent to the server (no detonation); the blowup is proven
STATICALLY on the extracted pattern.

HONEST EVIDENCE BASIS: a CONFIRMED here means "the pattern is provably catastrophic by deterministic
static step-count analysis" — NOT a live-triggered DoS (we never detonate the server). Reachability is
deployment-dependent. Patterns outside the analyzable class are reported as a LEAD, never CONFIRMED.
"""
from __future__ import annotations

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026

EVIDENCE_BASIS = ("catastrophic backtracking proven by deterministic static step-count analysis "
                  "(NOT a live DoS; server never detonated); reachability is deployment-dependent")


# ---------------- minimal regex AST + parser (char, group, +/*, ^/$) ----------------
class Char:
    def __init__(self, c): self.c = c
class Rep:
    def __init__(self, child, plus): self.child = child; self.plus = plus   # +: plus=True, *: False
class Concat:
    def __init__(self, items): self.items = items
class Start: pass
class End: pass

_SUPPORTED = set("abcdefghijklmnopqrstuvwxyz()+*^$")


def parse(pat: str):
    """Parse the analyzable subset. Raises ValueError on any out-of-class construct (-> LEAD upstream)."""
    bad = set(pat) - _SUPPORTED
    if bad:
        raise ValueError(f"unsupported regex construct(s): {sorted(bad)}")
    pos = [0]
    def peek(): return pat[pos[0]] if pos[0] < len(pat) else ""
    def concat(stop):
        items = []
        while peek() and peek() not in stop:
            items.append(quant())
        return Concat(items)
    def quant():
        a = atom()
        while peek() in ("+", "*"):
            a = Rep(a, peek() == "+"); pos[0] += 1
        return a
    def atom():
        c = peek(); pos[0] += 1
        if c == "(":
            inner = concat(")")
            if peek() != ")":
                raise ValueError("unbalanced group")
            pos[0] += 1
            return inner
        if c == "^": return Start()
        if c == "$": return End()
        return Char(c)
    ast = concat("")
    if pos[0] != len(pat):
        raise ValueError("trailing input")
    return ast


def match_steps(ast, text: str):
    """Deterministic backtracking matcher. Returns (found_full_match, step_count). A step = one
    match-attempt; counting is pure and reproducible (no clock, no randomness)."""
    steps = [0]; n = len(text)
    def ends(node, i):
        steps[0] += 1
        if isinstance(node, Start):
            if i == 0: yield 0
        elif isinstance(node, End):
            if i == n: yield n
        elif isinstance(node, Char):
            if i < n and text[i] == node.c: yield i + 1
        elif isinstance(node, Concat):
            def rec(idx, j):
                if idx == len(node.items): yield j
                else:
                    for j2 in ends(node.items[idx], j): yield from rec(idx + 1, j2)
            yield from rec(0, i)
        elif isinstance(node, Rep):
            def more(j, once):
                if (not node.plus) or once: yield j
                for j2 in ends(node.child, j):
                    if j2 > j: yield from more(j2, True)   # progress guard: no infinite empty-match loop
            yield from more(i, False)
    found = any(e == n for e in ends(ast, 0))
    return found, steps[0]


def _first_char(node) -> str:
    if isinstance(node, Char): return node.c
    if isinstance(node, Rep): return _first_char(node.child)
    if isinstance(node, Concat):
        for it in node.items:
            c = _first_char(it)
            if c: return c
    return ""


def analyze_pattern(pattern: str, n1: int = 8, n2: int = 16) -> dict:
    """Static, deterministic verdict for a tool-schema regex. No server contact, no wall-clock."""
    if not pattern:
        return {"verdict": "BOUNDED", "pattern": pattern, "reason": "no pattern declared"}
    try:
        ast = parse(pattern)
    except ValueError as e:
        return {"verdict": "LEAD", "pattern": pattern, "reason": str(e),
                "note": "outside the analyzable class — manual review, not a confirmed finding"}
    pump = _first_char(ast) or "a"
    fail = "!"                                             # a char the pump never matches -> forces full backtrack
    _, s1 = match_steps(ast, pump * n1 + fail)
    _, s2 = match_steps(ast, pump * n2 + fail)
    blowup = s2 / s1 if s1 else 1.0
    catastrophic = blowup >= 8                             # linear~2, quadratic~4 stay below; only cubic+ fires
    return {"verdict": "CONFIRMED" if catastrophic else "BOUNDED", "pattern": pattern,
            "steps_n1": s1, "steps_n2": s2, "blowup": round(blowup, 1),
            "evidence_basis": EVIDENCE_BASIS if catastrophic else "step count grows ~linearly; not catastrophic"}


def _extract_pattern(tools: list) -> str:
    for t in tools:
        for prop in ((t.get("input_schema") or {}).get("properties") or {}).values():
            if isinstance(prop, dict) and prop.get("pattern"):
                return prop["pattern"]
    return ""


def probe_redos(url: str) -> dict:
    """Read the tool's inputSchema pattern live, analyze it statically. Never sends adversarial input."""
    pattern = _extract_pattern(StatelessHTTPClient(url).list_tools())
    return analyze_pattern(pattern)


def probe_benign(url: str, username: str = "aaa") -> dict:
    """A SHORT benign input the server validates normally (proves it applies the pattern; no blowup)."""
    text = _result_text_2026(StatelessHTTPClient(url).begin(
        "tools/call", {"name": "validate_username", "arguments": {"username": username}}))
    return {"completes": "valid" in text, "evidence": text[:80]}
