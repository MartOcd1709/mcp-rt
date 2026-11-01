"""Explain-the-exploit chain (T7 / SAM1-14): for an ORACLE-CONFIRMED finding, locate the root-cause
sink (`file:line -> expr`) + a fix. Two backends behind one interface; honest failure is first-class.

The moat is unchanged: this is ADDITIVE. The canary/nonce oracle remains the only thing that decides a
verdict — the chain never promotes, demotes, or creates a finding. We never present an inferred line as
fact: when handler reachability is AMBIGUOUS we list candidates WITH confidence (CIO condition — a
false-precise `root cause: file:line` is as damaging as a false finding); we collapse to one line only
when reachability is unambiguous; and when we cannot locate it we say `COULD-NOT-LOCATE`, never guess.
"""
from __future__ import annotations

import ast
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from hunt.report import CLASS_META


@dataclass
class Candidate:
    file: str
    line: int
    expr: str
    reached: bool          # tied to the vulnerable tool's handler (reachability), vs merely present in the module


@dataclass
class SinkResult:
    cls: str
    tool: str
    candidates: list[Candidate]
    confidence: str        # "unambiguous" (one reached sink) | "ambiguous" (multiple / reachability unclear)
    provenance: str        # "source" | "rea:<evidence_id>"
    fix: str


@dataclass
class CouldNotLocate:
    cls: str
    tool: str
    reason: str
    fix: str                # fall back to the generic class fix — honest, never a fabricated line


# class -> how its dangerous sink looks as an AST Call. Matched on the call target (attr or bare name);
# command_injection additionally matches subprocess.* with shell=True. Conservative: when unsure we keep
# a candidate rather than collapse.
_SINK_FUNCS = {
    "command_injection": {"getoutput", "system", "popen", "getstatusoutput"},
    "arg_injection": {"run", "call", "Popen", "check_output", "check_call"},
    "path_traversal": {"open"},
    "ssti": {"eval", "exec", "compile", "render", "from_string"},
    "sql_injection": {"execute", "executemany", "executescript"},
    "deserialization": {"load", "loads"},
    "code_injection": {"eval", "exec", "compile"},
}


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _is_shell_true(node: ast.Call) -> bool:
    return any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
               for k in node.keywords)


def _matches(cls: str, node: ast.Call) -> bool:
    name = _call_name(node)
    if cls == "command_injection":
        return name in _SINK_FUNCS["command_injection"] or (name in {"run", "call", "Popen"} and _is_shell_true(node))
    if cls == "deserialization":
        # yaml.load / pickle.loads etc. — but NOT json.loads / yaml.safe_load
        if name == "load" and isinstance(node.func, ast.Attribute):
            return True  # yaml.load (safe_load is a different attr, excluded)
        return name == "loads" and isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", "") in {"pickle", "marshal", "dill"}
    return name in _SINK_FUNCS.get(cls, set())


def _branch_tools(if_node: ast.If) -> list[str]:
    """Tool names an `if name == 'x'` / `if name in ('x','y')` branch handles (else [])."""
    t = if_node.test
    if isinstance(t, ast.Compare) and len(t.ops) == 1:
        left, op, right = t.left, t.ops[0], t.comparators[0]
        if isinstance(left, ast.Name) and left.id == "name":
            if isinstance(op, ast.Eq) and isinstance(right, ast.Constant):
                return [right.value]
            if isinstance(op, ast.In) and isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                return [e.value for e in right.elts if isinstance(e, ast.Constant)]
    return []


def locate_sink(cls: str, tool: str, *, source_path: str | None = None,
                installed_dir: str | None = None) -> SinkResult | CouldNotLocate:
    """Locate the sink for a (class, tool). Readable source -> AST source-grep; else bundled JS -> REA;
    else honest COULD-NOT-LOCATE. Reachability from the tool handler sets the confidence."""
    fix = (CLASS_META.get(cls) or {}).get("fix", "apply the secure-design control for this class")
    if source_path and Path(source_path).is_file() and source_path.endswith(".py"):
        return _locate_source_py(cls, tool, source_path, fix)
    if installed_dir and Path(installed_dir).is_dir():
        return _locate_rea_js(cls, tool, installed_dir, fix)
    return CouldNotLocate(cls, tool, f"no readable source / supported runtime for target", fix)


def _locate_source_py(cls: str, tool: str, source_path: str, fix: str) -> SinkResult | CouldNotLocate:
    src = Path(source_path).read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return CouldNotLocate(cls, tool, f"source parse error: {e}", fix)
    fname = Path(source_path).name
    helpers = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

    def sinks_in(nodes) -> list[Candidate]:
        out = []
        for n in nodes:
            for c in ast.walk(n):
                if isinstance(c, ast.Call) and _matches(cls, c):
                    expr = (ast.get_source_segment(src, c) or _call_name(c))[:160]
                    out.append(Candidate(fname, c.lineno, expr, reached=True))
        return out

    # find the handler branch(es) for this tool and the sinks reachable from them (branch body + 1 hop)
    reached: list[Candidate] = []
    for if_node in (n for n in ast.walk(tree) if isinstance(n, ast.If)):
        if tool in _branch_tools(if_node):
            body = list(if_node.body)
            # one hop: follow calls to module-level helpers named in this branch
            for c in ast.walk(if_node):
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in helpers:
                    body.append(helpers[c.func.id])
            reached.extend(sinks_in(body))

    # dedup by (line, expr)
    seen = set()
    reached = [c for c in reached if (c.line, c.expr) not in seen and not seen.add((c.line, c.expr))]

    if len(reached) == 1:
        return SinkResult(cls, tool, reached, "unambiguous", "source", fix)
    if len(reached) > 1:
        return SinkResult(cls, tool, reached, "ambiguous", "source", fix)  # CIO: list candidates, don't guess one

    # no sink reachable from the handler. Rather than a false-precise line, surface module-level
    # candidates (reached=False) with ambiguous confidence, or honestly could-not-locate.
    module_hits = sinks_in(tree.body)
    for c in module_hits:
        c.reached = False
    if module_hits:
        return SinkResult(cls, tool, module_hits, "ambiguous", "source", fix)
    return CouldNotLocate(cls, tool, f"no {cls} sink found in {fname}", fix)


def _locate_rea_js(cls: str, tool: str, installed_dir: str, fix: str) -> SinkResult | CouldNotLocate:
    """Compiled/bundled JS: recover the sink via REA's JavaScript application analysis, carrying REA's
    evidence id as provenance. Degrades honestly to COULD-NOT-LOCATE — never a guessed line."""
    import json
    import shutil
    import subprocess
    if not shutil.which("rea"):
        return CouldNotLocate(cls, tool, "rea CLI not available for compiled-JS analysis", fix)
    js_sinks = {"command_injection": ("child_process", "exec", "execSync", "spawn"),
                "ssti": ("eval", "Function"), "path_traversal": ("readFile", "createReadStream", "open"),
                "sql_injection": ("query", "execute"), "deserialization": ("eval", "Function")}
    terms = js_sinks.get(cls, ())
    try:
        p = subprocess.run(["rea", "analyze-javascript-application", installed_dir,
                            "--artifact-format", "directory", "--format", "json"],
                           capture_output=True, text=True, timeout=180)
        if p.returncode != 0:
            return CouldNotLocate(cls, tool, f"rea failed: {p.stderr[:120]}", fix)
        ev = json.loads(p.stdout)
        evid = ev.get("evidence_id", "rea")
        blob = json.dumps(ev.get("normalized_result", {}))
        if terms and any(t in blob for t in terms):
            # REA found the dangerous builtin; we carry its evidence id as provenance but do NOT fabricate
            # a precise line we can't pin from here — report as an ambiguous REA-backed candidate.
            return SinkResult(cls, tool, [Candidate("<rea-graph>", 0, f"{cls} sink present ({'/'.join(terms)})", reached=False)],
                              "ambiguous", f"rea:{evid}", fix)
        return CouldNotLocate(cls, tool, f"rea located no {cls} sink (evidence {evid})", fix)
    except Exception as e:  # noqa: BLE001
        return CouldNotLocate(cls, tool, f"rea analysis error: {type(e).__name__}", fix)


def explain_chain(proof, *, source_path: str | None = None, installed_dir: str | None = None) -> str | None:
    """Render the explain-the-exploit chain for an ORACLE-CONFIRMED proof. Returns None for an
    unconfirmed finding (confirmed-only guard) — a lead NEVER gets a chain."""
    if not getattr(proof, "confirmed", False):
        return None   # confirmed-only: leads get no chain, ever
    cls, tool = proof.vuln_class, proof.tool
    res = locate_sink(cls, tool, source_path=source_path, installed_dir=installed_dir)
    head = f"VULNERABLE: {cls} in {tool}   [mcp-rt: {proof.signal or 'oracle confirmed'}]"
    if isinstance(res, CouldNotLocate):
        return f"{head}\n  Root cause:  COULD-NOT-LOCATE ({res.reason})\n  Fix:         {res.fix}"
    if res.confidence == "unambiguous":
        c = res.candidates[0]
        return (f"{head}\n  Root cause:  {c.file}:{c.line}  ->  {c.expr}  [{res.provenance}]\n  Fix:         {res.fix}")
    lines = "\n".join(f"    - {c.file}:{c.line} -> {c.expr}" + ("  (reached from handler)" if c.reached else "")
                      for c in res.candidates)
    return (f"{head}\n  Root cause:  AMBIGUOUS — candidates (confidence: {res.confidence}, {res.provenance}):\n{lines}\n  Fix:         {res.fix}")


def source_path_from_target(target) -> str | None:
    """Best-effort: pull a readable .py source path out of a stdio launch command (e.g. 'python foo.py')."""
    argv = shlex.split(target) if isinstance(target, str) else list(target)
    for a in argv:
        if a.endswith(".py") and Path(a).is_file():
            return a
    return None
