"""Provenance lane — repo-level static detection of trojanized MCP / agent-skill repos.

Acquisition-time threat (OWASP MCP04 / SAFE-T1003): the server code is clean; the weapon lives
in the REPO — a committed or staged payload plus a README instruction to run it — and it executes
on the dev/agent host during `git clone` / install, BEFORE the server is ever run under any scanner.
A behavioural oracle structurally cannot catch it: by the time there is runtime behaviour, the
payload already ran. So this is a distinct, complementary lane.

BOUNDARY (so nothing falls between modules):
  * provenance.py (this) = repo artifacts + README/docs + git history (acquisition-time).
  * hunt/supply_chain.py = npm pre/postinstall hooks, dependency/manifest tampering (package/runtime).
  * the runtime oracle = behaviour when the server is actually run.

DISCIPLINE:
  * Static only. Never opens/extracts an archive, never executes anything. Reads file headers
    (magic bytes) and text content as DATA.
  * Target-driven. No hardcoded repo / account / tool / payload names (Ved's standing law).
  * Output = per-signal evidence + a fused verdict (CLEAN / SUSPECT / HIGH_RISK). In the unified
    report these are LEADS, never oracle-VULNERABLE — static-inferred provenance, not runtime proof.

Signals (see PROVENANCE_LANE_CASE_MATRIX.md):
  a committed-artifact     archive / executable / native-lib / disguised-script in the tree
  b readme-lure            prose telling the user to run a committed/downloaded binary or click
                           past an OS security warning (NOT the project's own documented commands,
                           NOT research "detonate in a sandbox" phrasing)
  c agent-config-payload   an obfuscated/disguised/binary payload under .claude/hooks|skills|commands,
                           config/ etc. A plain readable hook script with an honest extension is
                           legit-by-default and does NOT fire (the campaign's tell is obfuscation).
  d impersonation (static) conservative clone/redirect tell. Owner-age + registry cross-listing need
                           the network and are DEFERRED — logged as a stated recall gap, never a
                           silent cap.
  e commit-anomaly         long clean git history then a single README-/artifact-only change (hijack).

The README run-lure (b) is the pivot: a trojan is payload + instruction-to-run; a defensive/research
repo is payload + analysis docs with NO run-lure. When security-docs context is present and (b) is
absent, the verdict is capped at SUSPECT (never HIGH_RISK).
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
from pathlib import Path

CLEAN, SUSPECT, HIGH_RISK = "CLEAN", "SUSPECT", "HIGH_RISK"

# --- file-type knowledge (extension + magic), no hardcoded project/payload names ---
_ARCHIVE_EXT = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso"}
_EXE_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".bat", ".cmd", ".com", ".scr",
            ".vbs", ".jar", ".apk", ".deb", ".rpm", ".wasm", ".luac", ".ps1"}
_MAGIC = [  # (prefix bytes, kind)
    (b"PK\x03\x04", "archive"), (b"PK\x05\x06", "archive"), (b"Rar!\x1a\x07", "archive"),
    (b"7z\xbc\xaf\x27\x1c", "archive"), (b"\x1f\x8b", "archive"), (b"\xfd7zXZ", "archive"),
    (b"MZ", "executable"), (b"\x7fELF", "executable"),
    (b"\xca\xfe\xba\xbe", "executable"), (b"\xcf\xfa\xed\xfe", "executable"),
    (b"\xce\xfa\xed\xfe", "executable"), (b"\x1bLua", "executable"), (b"\x1bLJ", "executable"),
]
# data/doc extensions where a payload would be DISGUISED (code hiding as text)
_DATA_EXT = {".txt", ".md", ".rst", ".json", ".dat", ".log", ".cfg", ".ini", ".csv", ".yaml", ".yml"}
# honest script extensions — a READABLE one of these under an agent-config dir is legit (N7)
_SCRIPT_EXT = {".py", ".sh", ".js", ".ts", ".rb", ".pl", ".lua", ".mjs", ".bash", ".zsh"}
_AGENT_CONFIG_DIRS = (".claude/hooks", ".claude/skills", ".claude/commands", ".claude/agents",
                      ".cursor", ".continue", "config")
_README_RE = re.compile(r"^(readme|install|setup|getting[-_ ]?started)\b", re.I)
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache"}

# (b) run-lure phrasing — telling an end user to RUN an opaque artifact / bypass an OS guard
_LURE_RUN = re.compile(
    r"\b(double[- ]?click|run|execute|launch)\b[^.\n]{0,60}"
    r"\b([\w./\\-]+\.(?:exe|bat|cmd|com|scr|msi|ps1|vbs|jar|zip|7z|rar))\b", re.I)
_LURE_EXTRACT = re.compile(r"\b(extract|unzip|unpack)\b[^.\n]{0,80}\b(run|execute|launch|double[- ]?click)\b", re.I)
_LURE_BYPASS = re.compile(
    r"smartscreen|protected your pc|run anyway|unknown publisher|more info.{0,20}run|"
    r"gatekeeper|allow anyway|open anyway|unidentified developer|"
    r"(disable|turn off|add an? exclusion|whitelist)[^.\n]{0,30}"
    r"(antivirus|defender|real[- ]?time protection|smartscreen)", re.I)
# research phrasing that must NOT be read as an end-user run-lure (N5/N6)
_RESEARCH_RUN = re.compile(r"\b(detonate|run|execute)\b[^.\n]{0,40}"
                           r"\b(sandbox|isolated vm|isolated virtual machine|analysis vm|cuckoo)\b", re.I)

_HASH_LINE = re.compile(r"^[\s*|>-]*[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8}){0,4}[\s|].*$|"
                        r"\b[0-9a-f]{64}\b", re.I)  # MD5/SHA1/SHA256 — an IOC table, not code
_SECURITY_DOCS = re.compile(
    r"\b(ioc|indicators? of compromise|malware analysis|threat (intel|report)|yara|"
    r"detection rule|defang|c2 |sha256|sha-256|cve-\d|advisory|coordinated disclosure)\b", re.I)
_CODE_TOKENS = re.compile(
    r"\b(function|local|require|loadstring|dofile|eval|exec|os\.(execute|getenv)|io\.popen|"
    r"subprocess|powershell|cmd\s*/c|CreateObject|WScript|Invoke-Expression|iex|base64|fromCharCode)\b")
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEXARR_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|(?:0x[0-9a-fA-F]{2}\s*,\s*){40,}")

LONG_HISTORY = 10          # commits; below this, "clean history → pivot" is not meaningful
# ponytail: thresholds are the calibration knob — tune against the battery, not the live repos.


def _magic_kind(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return None
    for prefix, kind in _MAGIC:
        if head.startswith(prefix):
            return kind
    return None


def _read_text(path: Path, cap: int = 200_000) -> str:
    try:
        return path.read_text("utf-8", errors="replace")[:cap]
    except OSError:
        return ""


def _looks_like_disguised_code(path: Path) -> bool:
    """A2 — a data/doc-extension file whose CONTENT is executable code / an obfuscated payload.

    Keys on code STRUCTURE, never on the mere presence of hex/base64: a hash list or hex IOC table
    (exactly N5/N6) must not trip this.
    """
    if path.suffix.lower() not in _DATA_EXT:
        return False
    text = _read_text(path, cap=400_000)
    if not text.strip():
        return False
    lines = text.splitlines()
    # precision guard: a file that is mostly hash/IOC lines is a research table, not code
    hashish = sum(1 for ln in lines if ln.strip() and _HASH_LINE.search(ln))
    if lines and hashish >= max(3, len(lines) // 2):
        return False
    # obfuscation / packing tells
    if _B64_RUN.search(text) and _CODE_TOKENS.search(text):
        return True                      # long base64 blob next to loadstring/eval/exec → disguised
    if _HEXARR_RUN.search(text):
        return True                      # big \xNN or 0xNN byte array
    # packed one-liner: a very long line dense with code punctuation
    for ln in lines:
        if len(ln) >= 1000 and sum(ln.count(c) for c in "{}();=>") >= 40:
            return True
    # high density of scripting control-flow tokens relative to size (script hiding as .txt/.md)
    if len(_CODE_TOKENS.findall(text)) >= 8 and path.suffix.lower() in {".txt", ".dat", ".log"}:
        return True
    return False


def _artifact_kind(path: Path) -> str | None:
    """'archive' | 'executable' | 'disguised-script' | None — static, header + content only."""
    ext = path.suffix.lower()
    if ext in _ARCHIVE_EXT:
        return "archive"
    if ext in _EXE_EXT:
        return "executable"
    magic = _magic_kind(path)
    if magic:
        return magic
    if _looks_like_disguised_code(path):
        return "disguised-script"
    return None


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def _rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def _in_agent_config(rel: str) -> bool:
    r = rel.replace("\\", "/").lower()
    return any(r.startswith(d + "/") or ("/" + d + "/") in ("/" + r) for d in _AGENT_CONFIG_DIRS)


# --- signals ---------------------------------------------------------------

def _sig_committed_artifact(root: Path):
    hits = []
    for p in _iter_files(root):
        rel = _rel(root, p)
        if _in_agent_config(rel):
            continue  # agent-config payloads belong to signal (c), counted there
        kind = _artifact_kind(p)
        if kind:
            hits.append({"path": rel, "kind": kind})
    return hits


def _sig_agent_config_payload(root: Path):
    """(c) — fires ONLY on a binary/archive/disguised or OBFUSCATED payload under an agent-config dir.
    A plain readable script with an honest extension (hook.py / hook.sh) is legit-by-default (N7)."""
    hits = []
    for p in _iter_files(root):
        rel = _rel(root, p)
        if not _in_agent_config(rel):
            continue
        ext = p.suffix.lower()
        kind = _artifact_kind(p)           # archive / executable / disguised-script
        if kind:
            hits.append({"path": rel, "kind": kind})
        elif ext in _SCRIPT_EXT and _looks_like_obfuscated_script(p):
            hits.append({"path": rel, "kind": "obfuscated-script"})
        # else: a readable honest-extension script → legit, no hit (N7 carve-out)
    return hits


def _looks_like_obfuscated_script(path: Path) -> bool:
    """An honest-extension script whose body is obfuscated (base64+eval, hex array, packed one-liner).
    This is what distinguishes a weaponised hook from a normal readable one."""
    text = _read_text(path, cap=400_000)
    if _B64_RUN.search(text) and _CODE_TOKENS.search(text):
        return True
    if _HEXARR_RUN.search(text):
        return True
    for ln in text.splitlines():
        if len(ln) >= 1000 and sum(ln.count(c) for c in "{}();=>") >= 40:
            return True
    return False


def _sig_readme_lure(root: Path):
    hits = []
    for p in _iter_files(root):
        if not _README_RE.match(p.name) and p.suffix.lower() not in {".md", ".rst", ".txt"}:
            continue
        if not (_README_RE.match(p.name) or "/docs/" in ("/" + _rel(root, p).replace("\\", "/"))):
            continue
        text = _read_text(p)
        if not text:
            continue
        for rx, why in ((_LURE_RUN, "run a committed/downloaded binary"),
                        (_LURE_EXTRACT, "extract then run an archive"),
                        (_LURE_BYPASS, "click past an OS security warning")):
            for m in rx.finditer(text):
                span = text[max(0, m.start() - 40):m.end() + 40]
                if _RESEARCH_RUN.search(span):
                    continue               # research "detonate in a sandbox" — not an end-user lure
                hits.append({"path": _rel(root, p), "why": why, "evidence": m.group(0)[:120]})
    return hits


def _sig_impersonation(root: Path):
    """(d) static v1 — conservative clone/redirect tell only. Owner-age + registry are DEFERRED."""
    hits = []
    readme = next((p for p in _iter_files(root) if _README_RE.match(p.name)), None)
    if readme:
        text = _read_text(readme)
        # "official/original is at <other-owner URL>" while instructing to install from HERE = redirect-impersonation
        if re.search(r"\b(official|original|genuine|real)\b[^.\n]{0,40}https?://", text, re.I) and \
           re.search(r"\b(clone|download|install)\b[^.\n]{0,30}\b(this|here|below)\b", text, re.I):
            hits.append({"path": _rel(root, readme), "why": "redirect-impersonation shape (official source elsewhere)"})
    return hits


def _sig_commit_anomaly(root: Path):
    """(e) — long clean git history then a single README-/artifact-only latest change. Static git read."""
    if not (root / ".git").exists():
        return {"evaluated": False, "hits": []}
    def git(*a):
        try:
            return subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True,
                                  timeout=20).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
    try:
        total = int(git("rev-list", "--count", "HEAD").strip() or 0)
    except ValueError:
        total = 0
    if total < LONG_HISTORY:
        return {"evaluated": True, "hits": []}
    changed = [l for l in git("show", "--name-only", "--pretty=format:", "HEAD").splitlines() if l.strip()]
    if changed and all(_README_RE.match(Path(f).name) or _artifact_kind(root / f)
                       for f in changed):
        return {"evaluated": True, "hits": [{"why": f"{total}-commit history; latest touches only "
                                             f"README/artifact files", "files": changed[:10]}]}
    return {"evaluated": True, "hits": []}


def _security_docs_context(root: Path) -> bool:
    for p in _iter_files(root):
        if p.suffix.lower() in {".md", ".rst", ".txt", ".yar", ".yara"} or p.name.upper().startswith("SECURITY"):
            if _SECURITY_DOCS.search(_read_text(p, cap=50_000)):
                return True
    return False


# --- fusion ----------------------------------------------------------------

# HIGH when any of these signal pairs co-occur (every triple+ contains one of these pairs).
_HIGH_PAIRS = [frozenset(p) for p in
               (("a", "b"), ("b", "c"), ("a", "c"), ("a", "e"), ("b", "e"), ("c", "e"), ("c", "d"))]


def _fuse(fired: set[str], security_docs: bool) -> str:
    if not fired:
        return CLEAN
    high = any(pair <= fired for pair in _HIGH_PAIRS)
    if high and not (security_docs and "b" not in fired):
        return HIGH_RISK
    return SUSPECT          # single signal, or capped research-repo context, or a SUSPECT pair


def analyze_repo(path: str | os.PathLike) -> dict:
    """Static provenance analysis of a repo (local clone). Returns per-signal evidence + fused verdict."""
    root = Path(path).resolve()
    a = _sig_committed_artifact(root)
    b = _sig_readme_lure(root)
    c = _sig_agent_config_payload(root)
    d = _sig_impersonation(root)
    e = _sig_commit_anomaly(root)
    security_docs = _security_docs_context(root)

    fired = set()
    if a: fired.add("a")
    if b: fired.add("b")
    if c: fired.add("c")
    if d: fired.add("d")
    if e["hits"]: fired.add("e")

    verdict = _fuse(fired, security_docs)
    capped = verdict == SUSPECT and security_docs and "b" not in fired and any(
        pair <= fired for pair in _HIGH_PAIRS)

    gaps = ["owner-account age/reputation (network pass pending)",
            "registry cross-listing (network pass pending)"]
    if not e["evaluated"]:
        gaps.append("commit-anomaly not evaluated (no git history at this path)")

    return {
        "target": str(root),
        "verdict": verdict,
        "capped_by_security_docs": capped,
        "security_docs_context": security_docs,
        "signals": {"committed_artifact": a, "readme_lure": b, "agent_config_payload": c,
                    "impersonation": d, "commit_anomaly": e["hits"]},
        "fired": sorted(fired),
        "recall_gaps": gaps,              # stated, never a silent cap (Ved's law)
        "why": "provenance (repo artifacts + install prose + history), not runtime behaviour",
    }


def main(argv=None) -> int:
    import json
    import sys
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage: mcp-rt provenance <repo-path>", file=sys.stderr)
        return 2
    print(json.dumps(analyze_repo(args[0]), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
