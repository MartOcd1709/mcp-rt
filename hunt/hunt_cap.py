"""MCP-00 hunting harness — Leg 1: MCP-CAP (Undeclared-Capability / Consent-Gap).

A tool that exercises a capability its schema never declared — opens a socket when it claimed
file-read-only, writes when it claimed read, spawns a process — is a consent gap: the host granted
one capability and got another. We don't INFER it; we OBSERVE it: run the server under an strace
sensor, call each tool once with benign args, and compare the syscalls it actually made against
what its schema declared. A gap is a HYPOTHESIS, never a finding, until confirmed end-to-end.

Design: docs/HUNT_HARNESS_MCP00.md. Discipline: ground-truth only; observed, not inferred; a read
is never flagged; a declared capability exercised is by-design, not a gap.

The zero-FP-critical core (`declared_caps`, `parse_strace_caps`, `classify_gaps`) is pure and tested.
The live runner (`run_cap_hunt`) degrades honestly to INCONCLUSIVE if strace is unavailable — it never
reports a false CLEAN.
"""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field

from .probes import _URL_PARAM, _schema

CAP_NETWORK, CAP_WRITE, CAP_EXEC, CAP_READ = "network", "write", "exec", "read"

# What a tool DECLARES, read from its own text. Whole words only, and only where a word states what the tool does:
# a token of the tool's NAME, or the leading verb of a sentence in its description. Substring matching used to let
# "description" declare running programs (it contains "script"), "credit" declare writing ("edit") and a noun such
# as "the commit logs" declare writing — so the check could be switched off by an innocent word as easily as it
# could be noisy. There is no list of program names here: which helper a tool may run is read from the server
# itself (see _helper_names).
_VERBS = {
    CAP_NETWORK: {"fetch", "download", "upload", "crawl", "scrape", "request", "post", "send", "sync", "publish",
                  "notify", "email", "connect", "browse", "navigate", "push", "pull"},
    CAP_WRITE: {"write", "create", "save", "edit", "append", "put", "modify", "move", "rename", "delete", "remove",
                "unlink", "mkdir", "copy", "upload", "store", "insert", "update", "patch", "touch", "set", "persist",
                "commit", "export", "download", "add", "init", "initialize", "archive", "install"},
    CAP_EXEC: {"run", "execute", "exec", "spawn", "invoke", "launch", "build", "compile", "eval", "evaluate"},
}
# nouns that state a capability when they are part of the tool's NAME (http_get, run_shell); never from prose
_NAME_NOUNS = {
    CAP_NETWORK: {"http", "https", "url", "uri", "web", "api", "webhook", "remote", "dns", "rss", "feed", "smtp"},
    CAP_WRITE: set(),
    CAP_EXEC: {"shell", "command", "cmd", "script", "terminal", "subprocess"},
}
_URL_ARG = re.compile(r"(?<![a-z])(url|uri|href|link|endpoint|webhook)(?![a-z])", re.I)   # an argument that IS a URL
_FILLER = {"this", "tool", "the", "a", "an", "it", "to", "will", "can", "also", "then", "please", "you", "use", "used"}
_SENTENCE = re.compile(r"[.!?;\n]+")
_USES = re.compile(r"\b(?:via|using|through|wraps?|calls?|runs?|invokes?)\s+(?:the\s+)?`?([A-Za-z][\w.+-]*)", re.I)


def _tokens(text: str) -> list[str]:
    """Lower-case words of a name or sentence; camelCase and snake_case both split."""
    return [t.lower() for t in re.findall(r"[A-Za-z][a-z]*|\d+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text or ""))]


def _stems(word: str) -> set[str]:
    """A verb and its plain forms: fetches / fetched / fetching -> fetch, saving -> save."""
    w = word.lower()
    out = {w}
    for suf, add in (("ies", "y"), ("es", ""), ("s", ""), ("ed", ""), ("ed", "e"), ("d", ""), ("ing", ""), ("ing", "e")):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            out.add(w[: len(w) - len(suf)] + add)
    return out


def _leading_verbs(description: str) -> set[str]:
    """The first content word of each sentence, in its plain forms."""
    out: set[str] = set()
    for sentence in _SENTENCE.split(description or ""):
        word = next((t for t in _tokens(sentence) if t not in _FILLER), "")
        if word:
            out |= _stems(word)
    return out


@dataclass
class Hypothesis:
    """A surfaced anomaly awaiting confirmation. NEVER counted as a finding until the canary fires."""
    leg: str               # "mcp-cap"
    tool: str
    observation: str
    confirmable: bool       # can the engine auto-confirm it end-to-end?
    confirm_plan: str
    caps_declared: list = field(default_factory=list)
    caps_observed: list = field(default_factory=list)
    cap: str = ""           # the one capability this lead is about
    detail: str = ""        # what it acted on: the program, the path, the address


# ---- declared capability (what the tool's schema/description advertises) -----------------
def declared_caps(tool) -> set[str]:
    """Capabilities a tool openly advertises: a capability word in its name, the leading verb of a sentence in its
    description, or (for network) an argument that is a URL. Used only to recognise by-design behaviour."""
    name_tokens = set(_tokens(getattr(tool, "name", "") or ""))
    verbs = _leading_verbs(getattr(tool, "description", "") or "")
    caps = {cap for cap in (CAP_NETWORK, CAP_WRITE, CAP_EXEC)
            if (name_tokens | verbs) & _VERBS[cap] or name_tokens & _NAME_NOUNS[cap]}
    if any(_URL_ARG.search(re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", p)) for p in (_schema(tool).get("properties") or {})):
        caps.add(CAP_NETWORK)   # ponytail: any destination; narrow to the URL the caller passed once the traced
    return caps                 # call sends a real one (today it sends a placeholder, so nothing is fetched)


def _helper_names(tool, identity: str = "") -> set[str]:
    """Programs this tool is plainly a front end for, read from the server itself: the words of the tool's name, the
    words of the server's identity (its launch command and the name it gives itself), and any program its
    description says it uses ("... via <program>"). Version digits are ignored, so python3.12 is python."""
    words = set(_tokens(getattr(tool, "name", "") or "")) | set(_tokens(identity))
    words |= {m.group(1).lower() for m in _USES.finditer(getattr(tool, "description", "") or "")}
    return {_program(w) for w in words if len(w) >= 2}


def _program(path: str) -> str:
    """A program's bare name: no folder, no '#2' repeat marker, no version digits."""
    base = re.split(r"[\\/]", path.split("#", 1)[0])[-1].lower()
    return re.sub(r"[\d.]+$", "", base) or base


# ---- observed capability (what the syscalls prove the tool actually did) -----------------
# strace -f -ttt -e trace=network,openat,execve,unlink,unlinkat,rename,mkdir
_RE_CONNECT_INET = re.compile(r"\bconnect\(.*(AF_INET|sin_addr|inet_addr|sin6_addr)")
_RE_SOCKET_INET = re.compile(r"\bsocket\(AF_INET")
_RE_EXECVE = re.compile(r"\bexecve\(")
_RE_OPEN_WRITE = re.compile(r"\bopenat?\(.*\b(O_WRONLY|O_RDWR|O_CREAT|O_APPEND|O_TRUNC)\b")
_RE_FS_MUTATE = re.compile(r"\b(unlink|unlinkat|rename|renameat|mkdir|mkdirat)\(")
# Local IPC / self-pipes are NOT egress; strace shows AF_UNIX/AF_LOCAL for those — never flag them.
_RE_LOCAL_SOCK = re.compile(r"AF_(UNIX|LOCAL|NETLINK)")
# Paths that are not a real client-data write even when opened writable (device/kernel/tty noise).
_RE_BENIGN_WRITE_PATH = re.compile(r'"(/dev/|/proc/|/sys/|.*\.sock)')
_RE_FAILED = re.compile(r"=\s*-1\s+E")                       # the call failed: nothing was written or created
# `strace -y` names what a descriptor points at: the directory a relative path is resolved against, and the real
# (symlink-resolved) path of the file an open returned.
_RET_PATH = re.compile(r"=\s*\d+<([^>]+)>\s*$")
_DIRFD = re.compile(r"\((?:AT_FDCWD|\d+)<([^>]+)>")


_QUOTED = re.compile(r'"([^"]*)"')                 # first quoted string = path for open/exec/unlink
_INET_ADDR = re.compile(r'inet_addr\("([^"]+)"\)|sin_addr=inet_addr\("([^"]+)"\)|'
                        r'inet_pton\([^,]+,\s*"([^"]+)"')


def _first_quoted(ln: str) -> str:
    m = _QUOTED.search(ln)
    return m.group(1) if m else ""


def _inet_detail(ln: str) -> str:
    m = _INET_ADDR.search(ln)
    return (m.group(1) or m.group(2) or m.group(3)) if m else "inet"


@dataclass(frozen=True)
class Record:
    """One thing a traced process did, WITH what it acted on."""
    cap: str
    detail: str               # as the trace shows it: program (numbered "#2" when run again), address, or path
    path: str = ""            # writes: the resolved absolute path when the trace gives one, else ""
    exclusive: bool = False   # the file was created with O_EXCL: a name this call itself just made
    made_dir: bool = False    # mkdir: a directory this call itself just made

    @property
    def key(self) -> str:
        return self.path or self.detail


def _resolved(ln: str, quoted: str) -> str:
    """The absolute path a write acted on, or "" when the trace cannot tell (a bare relative path)."""
    ret = _RET_PATH.search(ln)
    if ret:
        return ret.group(1)
    if quoted.startswith("/"):
        return os.path.normpath(quoted)
    base = _DIRFD.search(ln)
    return os.path.normpath(os.path.join(base.group(1), quoted)) if base and quoted else ""


def parse_strace_records(lines) -> list[Record]:
    """Reduce strace output to what the child did: programs run, internet connections, and writes. Reads are never
    returned; local IPC, device files, byte-code caches and calls that FAILED are excluded.
    Execs are counted per binary: the launch is `/usr/bin/python`, a SECOND spawn of the same interpreter is
    `/usr/bin/python#2`. Otherwise a tool that runs `python -c ...` / `node -e ...` would hide behind the server's
    own launch in the baseline."""
    out: list[Record] = []
    seen_exec: dict[str, int] = {}
    for ln in lines:
        if _RE_EXECVE.search(ln) and "= -1" not in ln:          # a failed execve (PATH probing) spawned nothing
            binary = _first_quoted(ln)
            seen_exec[binary] = seen_exec.get(binary, 0) + 1
            n = seen_exec[binary]
            out.append(Record(CAP_EXEC, binary if n == 1 else f"{binary}#{n}"))
        if (_RE_CONNECT_INET.search(ln) or _RE_SOCKET_INET.search(ln)) and not _RE_LOCAL_SOCK.search(ln):
            out.append(Record(CAP_NETWORK, _inet_detail(ln)))
        if _RE_FAILED.search(ln):
            continue
        mutate = _RE_FS_MUTATE.search(ln)
        if mutate:
            quoted = _QUOTED.findall(ln)
            target = quoted[-1] if mutate.group(1).startswith("rename") and quoted else (quoted[0] if quoted else "")
            out.append(Record(CAP_WRITE, quoted[0] if quoted else "", _resolved(ln, target),
                              made_dir=mutate.group(1).startswith("mkdir")))
        elif _RE_OPEN_WRITE.search(ln):
            path = _first_quoted(ln)
            real = _resolved(ln, path)
            if (not _RE_BENIGN_WRITE_PATH.search(ln) and not real.startswith(("/dev/", "/proc/", "/sys/"))
                    and "__pycache__" not in path and not path.endswith(".pyc")):
                out.append(Record(CAP_WRITE, path, real, exclusive="O_EXCL" in ln))
    return out


def parse_strace_events(lines) -> set[tuple[str, str]]:
    """The (capability, detail) pairs in these lines; see parse_strace_records for what is kept."""
    return {(r.cap, r.detail) for r in parse_strace_records(lines)}


def caps_from_events(events) -> set[str]:
    return {cap for cap, _ in events}


def _dirname(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else path


_SEG_SPLIT = re.compile(r"/+")


def volatile_templates(b1_paths, b2_paths) -> list[re.Pattern]:
    """Paths whose NAME changes between two identical startups (mkdtemp dirs, per-run logs, random cache keys)
    are startup noise by definition. Each such pair becomes a template: the segments that differ are wildcards
    (keeping their common prefix/suffix), so the same churn in a per-tool launch is never mistaken for the tool."""
    out: list[re.Pattern] = []
    a_only, b_only = set(b1_paths) - set(b2_paths), set(b2_paths) - set(b1_paths)
    for pa in sorted(a_only):
        sa = _SEG_SPLIT.split(pa)
        for pb in sorted(b_only):
            sb = _SEG_SPLIT.split(pb)
            if len(sa) != len(sb):
                continue
            diff = [i for i, (x, y) in enumerate(zip(sa, sb)) if x != y]
            if not 1 <= len(diff) <= 2:
                continue
            parts = []
            for i, (x, y) in enumerate(zip(sa, sb)):
                if i not in diff:
                    parts.append(re.escape(x))
                    continue
                pre = len(os.path.commonprefix([x, y]))
                suf = len(os.path.commonprefix([x[::-1], y[::-1]]))
                suf = min(suf, len(x) - pre, len(y) - pre)
                parts.append(re.escape(x[:pre]) + r"[^/]+" + (re.escape(x[len(x) - suf:]) if suf else ""))
            out.append(re.compile("^" + "/".join(parts) + "$"))
            break
    return out


_BLIND = re.compile(r"(^\^?|/)\[\^/\]\+(/|\$)")      # a whole path segment that is nothing but a wildcard


def _volatile(path: str, templates, own: bool = True) -> bool:
    """Does this path match a name that changes on every launch? A template with a segment that is ALL wildcard
    (two startups made /tmp/k3j2h1g0 and /tmp/z9y8x7w6) would match every name in that folder, so it only cancels
    a path the process itself just created (`own`: an exclusive create or a mkdir), never a fixed name."""
    return any((t.match(path) or t.match(_dirname(path))) and (own or not _BLIND.search(t.pattern)) for t in templates)


def novel_caps(tool_events, baseline, volatile=()) -> set[str]:
    """Capabilities a tool exercised that the startup baseline did NOT. Writes are compared at
    DIRECTORY granularity, not exact path: a launcher (npx/uvx/node) scribbles uniquely-named temp
    and log files every run (e.g. ~/.npm/_cacache/tmp/<random>), so exact-path diff never cancels
    that churn and every tool looks like it writes. A write counts as novel only if it lands in a
    directory the baseline never wrote to. Network/exec stay exact-match (they carry stable detail)."""
    base_write_dirs = {_dirname(p) for cap, p in baseline if cap == CAP_WRITE}
    base_other = {(cap, p) for cap, p in baseline if cap != CAP_WRITE}
    novel: set[str] = set()
    for cap, detail in tool_events:
        if cap == CAP_WRITE:
            if _dirname(detail) not in base_write_dirs and not _volatile(detail, volatile):
                novel.add(CAP_WRITE)
        elif (cap, detail) not in base_other:
            novel.add(cap)
    return novel


def parse_strace_caps(lines) -> set[str]:
    """Back-compat: the CAP_* set exercised in these lines (reads excluded, local IPC/cache excluded)."""
    return caps_from_events(parse_strace_events(lines))


# ---- the gate: declared vs observed -> hypotheses (pure, zero-FP-critical) ----------------
_CONFIRM = {
    CAP_NETWORK: "re-run with an egress honeytoken sink; a connect to it on a benign call confirms undeclared egress",
    CAP_WRITE: "re-run with a canary path watch; a write outside declared scope on a benign call confirms it",
    CAP_EXEC: "re-run with a sentinel-marker argv; the sentinel firing confirms an undeclared spawn (→ likely command_injection)",
}


def classify_gaps(tool_name: str, declared: set[str], observed: set[str]) -> list[Hypothesis]:
    """A gap = an observed capability that was NOT declared. Reads never count. Each gap is a
    HYPOTHESIS with a confirm plan — never a finding here."""
    out = []
    for cap in sorted(observed - declared):
        if cap == CAP_READ:
            continue
        out.append(Hypothesis(
            leg="mcp-cap", tool=tool_name,
            observation=f"tool '{tool_name}' exercised undeclared capability: {cap} "
                        f"(declared: {sorted(declared) or 'none'})",
            confirmable=True, confirm_plan=_CONFIRM[cap],
            caps_declared=sorted(declared), caps_observed=sorted(observed)))
    return out


# ---- per-event judgment: every traced action is judged WITH what it acted on ---------------------------------
# A capability set threw the object away, so "exec" could not tell a git front end running git from a date tool
# running an unrelated program, and "write" could not tell the repository the operator handed over from a shell
# startup file. Rules, first match wins:
#   0 a write to a sensitive file is never by design          (checked first, and by exact path against startup)
#   1 running the helper program the tool or server is plainly a front end for    -> by design
#   2 a write inside the workspace passed on the launch command line              -> by design
#   3 a temporary file the call itself created                                    -> by design
#   4 a capability the tool's own text declares (whole words)                     -> by design
#   otherwise                                                                     -> a lead that names the object
# Nothing ruled by-design is dropped: it is returned as a row, so the coverage table shows what was seen and why.
LEAD = "observed_undeclared"


@dataclass(frozen=True)
class Grants:
    """What the operator and the server itself establish before any tool is called."""
    dirs: tuple = ()                      # directories passed on the launch command line (resolved)
    files: tuple = ()                     # files passed on the launch command line (resolved)
    identity: str = ""                    # the launch command's words + the name the server gives itself
    runtime: frozenset = frozenset()      # programs startup itself ran: identity never implies running them again
    sensitive: frozenset = frozenset()    # files no server has business writing
    temp: str = "/tmp"
    home: str = ""

    @property
    def shared(self) -> frozenset:
        """Folders everything on the machine writes into: a startup file there says nothing about a tool's file."""
        return frozenset(p for p in (self.temp, self.home) if p)


@dataclass
class CapRow:
    """One judged outcome for a tool: a lead, a by-design capability, a clean call, or a call that told us nothing."""
    tool: str
    cap: str               # network | write | exec, or "" when the row is about the whole call
    method: str            # confirmation method; the verdict comes from probes.verdict_for
    detail: str = ""       # what it acted on (up to three named)
    why: str = ""
    declared: tuple = ()


def launch_grants(argv, env: dict | None = None, server_name: str = "", runtime=()) -> Grants:
    """Read the launch command line: directories and files named on it are the workspace the operator handed over
    (resolved, and never widened to a parent); its words are part of the server's identity."""
    import tempfile
    dirs, files, words = [], [], []
    for i, arg in enumerate(argv or []):
        value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        if not arg.startswith("-") or "=" in arg:
            words.append(re.split(r"[\\/]", value.rstrip("/\\"))[-1])
        if i == 0 or not value or (arg.startswith("-") and "=" not in arg):
            continue
        real = os.path.realpath(os.path.expanduser(value))
        if os.path.isdir(real) and real != os.path.sep:
            dirs.append(real)
        elif os.path.isfile(real):
            files.append(real)
    home = (env or os.environ).get("HOME") or os.path.expanduser("~")
    try:
        from mcp_rt.runtime.runner import _tamper_targets
        sensitive = frozenset(_tamper_targets(home))
    except Exception:  # noqa: BLE001 - without the list there is no floor to apply, the other rules still hold
        sensitive = frozenset()
    return Grants(tuple(dirs), tuple(files), " ".join(words + [server_name or ""]),
                  frozenset(_program(p) for p in runtime), sensitive, os.path.realpath(tempfile.gettempdir()),
                  os.path.realpath(home))


def _inside(path: str, root: str) -> bool:
    return bool(path and root) and (path == root or path.startswith(root.rstrip("/") + "/"))


def _in_workspace(path: str, g: Grants) -> bool:
    """Inside a directory passed at launch, or the file passed at launch and its own side files (a database's
    journal, a lock). A relative path the trace could not resolve is never inside."""
    if not path.startswith("/"):
        return False
    if any(_inside(path, d) for d in g.dirs):
        return True
    return any(path == f or (path.startswith(f) and path[len(f)] in "-.~_") for f in g.files)


def novel_records(records, baseline, volatile=(), sensitive=frozenset(), shared=frozenset()) -> list[Record]:
    """What a tool did that startup did not. `baseline` is a set of (capability, key). A write is startup noise when
    startup wrote that exact path, when its name is one that changes on every launch (volatile), or when startup
    wrote elsewhere in the same folder (a launcher's cache churn). That last, folder-level rule does NOT apply to a
    sensitive file or to a shared folder (the temp root, the home folder): a startup file there says nothing about
    a tool's file, and it used to hide every later write in the same place."""
    base_paths = {k for cap, k in baseline if cap == CAP_WRITE}
    base_dirs = {_dirname(k) for k in base_paths}
    base_other = {(cap, k) for cap, k in baseline if cap != CAP_WRITE}
    # names this very trace created (an exclusive create or a mkdir): removing or writing inside one is still its own
    own_paths = {r.key for r in records if r.cap == CAP_WRITE and (r.exclusive or r.made_dir)}
    out = []
    for r in records:
        if r.cap != CAP_WRITE:
            if (r.cap, r.detail) not in base_other:
                out.append(r)
        elif r.key in base_paths or _volatile(r.key, volatile, own=r.key in own_paths
                                              or any(_inside(r.key, d) for d in own_paths)):
            continue
        elif r.key in sensitive or _dirname(r.key) in shared or _dirname(r.key) not in base_dirs:
            out.append(r)
    return out


def judge(tool, records, grants: Grants, call_ok: bool = True) -> list[CapRow]:
    """Apply the rules to what one tool did beyond startup. One row per (capability, outcome, reason)."""
    name = getattr(tool, "name", "") or ""
    declared = declared_caps(tool)
    named = _helper_names(tool)                              # from the tool's own name and description
    implied = _helper_names(tool, grants.identity)           # ... plus the server's identity
    made = [r.key for r in records if r.made_dir and _inside(r.key, grants.temp)]
    created = {r.key for r in records if r.exclusive and _inside(r.key, grants.temp)}
    buckets: dict[tuple[str, str, str], list[str]] = {}

    def put(cap, method, why, obj):
        objs = buckets.setdefault((cap, method, why), [])
        if obj and obj not in objs:
            objs.append(obj)

    for r in records:
        if r.cap == CAP_EXEC:
            path, prog = r.detail.split("#", 1)[0], _program(r.detail)
            if _inside(path, grants.temp):
                put(CAP_EXEC, LEAD, "it ran a file from the temporary folder", path)
            elif prog in named or (prog in implied and prog not in grants.runtime):
                put(CAP_EXEC, "by_design", "the helper program this tool is a front end for", path)
            elif CAP_EXEC in declared:
                put(CAP_EXEC, "by_design", "the tool says it runs programs", path)
            else:
                put(CAP_EXEC, LEAD, "", path)
        elif r.cap == CAP_WRITE:
            path = r.key
            if path in grants.sensitive:
                put(CAP_WRITE, LEAD, "a sensitive file", path)
            elif _in_workspace(path, grants):
                put(CAP_WRITE, "by_design", "inside the workspace passed at launch", path)
            elif _inside(path, grants.temp) and (r.exclusive or r.made_dir or path in created
                                                 or any(_inside(path, d) for d in made)):
                put(CAP_WRITE, "by_design", "a temporary file the call itself created", path)
            elif CAP_WRITE in declared:
                put(CAP_WRITE, "by_design", "the tool says it writes", path)
            else:
                put(CAP_WRITE, LEAD, "", path)
        elif CAP_NETWORK in declared:
            put(CAP_NETWORK, "by_design", "the tool says it uses the network", r.detail)
        else:
            put(CAP_NETWORK, LEAD, "", r.detail)

    rows = []
    for (cap, method, why), objs in buckets.items():
        if cap == CAP_NETWORK and len(objs) > 1:
            objs = [o for o in objs if o != "inet"]           # a real address says more than "an internet socket"
        shown = ", ".join(objs[:3]) + (f" and {len(objs) - 3} more" if len(objs) > 3 else "")
        rows.append(CapRow(name, cap, method, shown, why, tuple(sorted(declared))))
    if not rows:
        rows.append(CapRow(name, "", "oracle_negative" if call_ok else "sandbox_not_exercised", "",
                           "the call ran and did nothing beyond what startup does" if call_ok else
                           "the tool refused the test input, so it may never have done its work",
                           tuple(sorted(declared))))
    return rows


_DID = {CAP_EXEC: "ran", CAP_WRITE: "wrote", CAP_NETWORK: "connected to"}


def hypothesis_of(row: CapRow) -> Hypothesis:
    """A lead row as the hypothesis record the ledger and the reports already understand."""
    reason = f" ({row.why})" if row.why else ""
    return Hypothesis(
        leg="mcp-cap", tool=row.tool,
        observation=f"tool '{row.tool}' exercised undeclared capability: {row.cap} — {_DID[row.cap]} {row.detail}"
                    f"{reason} (declared: {list(row.declared) or 'none'})",
        confirmable=True, confirm_plan=_CONFIRM[row.cap], caps_declared=list(row.declared),
        caps_observed=[row.cap], cap=row.cap, detail=row.detail)


def record_hypotheses(db, target_id: int, hyps: list[Hypothesis]) -> list[int]:
    """Persist Leg-1 hypotheses to the ledger's `hypotheses` table (separate from findings).
    Returns the row ids. Thin bridge so the core (above) stays free of DB imports."""
    return [db.add_hypothesis(
        target_id, leg=h.leg, tool=h.tool, observation=h.observation,
        confirmable=h.confirmable, confirm_plan=h.confirm_plan,
        caps_declared=h.caps_declared, caps_observed=h.caps_observed) for h in hyps]


def strace_available() -> bool:
    return shutil.which("strace") is not None


# ---- live runner (gated; degrades honestly) ----------------------------------------------
# No timestamps needed: attribution is by baseline-diff (fresh launch per tool), not wall-clock windows.
# -y: name what each descriptor points at, so a write is judged by its real, resolved path (parse_strace_records)
STRACE_ARGV = ["strace", "-f", "-y", "-qq", "-e",
               "trace=network,openat,execve,unlink,unlinkat,rename,renameat,mkdir,mkdirat"]

# Hard OS-level deadline for one strace-wrapped session (connect + list + one call + teardown),
# env-overridable. A tool that blocks forever server-side (e.g. an adb tool waiting on a device)
# can wedge Python-side context teardown, which no asyncio timeout can interrupt — so we also cap
# the whole process tree with the `timeout` coreutil, which SIGTERMs then SIGKILLs. No per-tool logic.
_CAP_SESSION_BUDGET_S = float(os.environ.get("MCPRT_CAP_SESSION_BUDGET_S", "25"))
_CAP_CONNECT_TIMEOUT_S = float(os.environ.get("MCPRT_CONNECT_TIMEOUT_S", "30"))


def _os_timeout_prefix(budget: float) -> list[str]:
    """`timeout -k <grace> <budget> …` if the coreutil exists, else no-op. Guarantees the whole
    strace+target+grandchild tree dies even if the client-side teardown blocks on a stuck child."""
    import shutil
    if shutil.which("timeout"):
        return ["timeout", "-k", "5", str(int(budget))]
    return []


def run_cap_hunt(argv: list[str], env: dict | None = None, call_timeout: float = 10.0):
    """Live MCP-CAP hunt. Returns (status, hypotheses). status in {"OK","INCONCLUSIVE"}.

    Launches the target UNDER strace (trace to a file so MCP stdout stays clean), lists its tools,
    calls each once with benign args, and attributes syscalls to the tool whose call window they fall
    in. Startup/`npx` download noise happens before the first window, so it's naturally excluded.

    INCONCLUSIVE (never a false CLEAN) when strace is missing — on a client/prod Linux box strace is
    present or one `apt install strace` away.
    ponytail: wall-clock window attribution is a heuristic ceiling; upgrade = per-PID/fd tracking or a
    net-namespace sandbox that blocks+logs egress per call (docs/HUNT_HARNESS_MCP00.md Q1).
    """
    status, rows = run_cap_audit(argv, env, call_timeout)
    leads = _Leads(hypothesis_of(r) for r in rows if r.method == LEAD)
    leads.rows = rows
    return (status, leads)


class _Leads(list):
    """The leads of one traced run. `.rows` carries every judged row of that same run (by design, clean,
    inconclusive), so a caller can show coverage without tracing the server a second time."""
    rows: list = []


def run_cap_audit(argv: list[str], env: dict | None = None, call_timeout: float = 10.0):
    """The same traced run as run_cap_hunt, returning EVERY judged row: the leads, what was ruled by design (with
    the program / path / address it concerned), calls that did nothing new, and calls that told us nothing.
    Returns (status, rows); status "INCONCLUSIVE" (never a false clean) when the trace could not be taken."""
    if not strace_available():
        return ("INCONCLUSIVE", [])
    import asyncio
    try:
        return ("OK", asyncio.run(_run_traced(argv, env, call_timeout)))
    except Exception:  # noqa: BLE001 — a handshake/launch failure is INCONCLUSIVE, not a false CLEAN
        return ("INCONCLUSIVE", [])


async def _trace_session(argv, env, call_timeout, call_tool_name, debug=False):
    """Launch the target under strace, run the handshake, optionally call ONE tool, and return
    (records, tools_by_name, info). `call_tool_name=None` yields the startup-only baseline. Per-tool launches
    give deterministic attribution — no wall-clock windowing, no clock-alignment assumptions.
    info: lines (how much trace came back), call_ok (the tool accepted the test input), server_name."""
    import os
    import tempfile
    import time as _time
    import asyncio as _asyncio
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from .probes import _build_args

    tracefile = tempfile.mktemp(prefix="mcprt_strace_", suffix=".log")
    # OS-level hard deadline wraps strace, which wraps the target — a stuck server-side child can't
    # outlive the budget even if client-side teardown blocks on it.
    wrapped = _os_timeout_prefix(_CAP_SESSION_BUDGET_S) + STRACE_ARGV + ["-o", tracefile, "--"] + list(argv)
    params = StdioServerParameters(command=wrapped[0], args=wrapped[1:], env=env or dict(os.environ))
    tools_by_name = {}
    info = {"lines": 0, "call_ok": None, "server_name": ""}
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            init = await _asyncio.wait_for(session.initialize(), _CAP_CONNECT_TIMEOUT_S)
            info["server_name"] = getattr(getattr(init, "serverInfo", None), "name", "") or ""
            for t in (await _asyncio.wait_for(session.list_tools(), _CAP_CONNECT_TIMEOUT_S)).tools:
                tools_by_name[t.name] = t
            if call_tool_name and call_tool_name in tools_by_name:
                try:
                    res = await _asyncio.wait_for(
                        session.call_tool(call_tool_name, _build_args(tools_by_name[call_tool_name], {})),
                        call_timeout)
                    info["call_ok"] = not getattr(res, "isError", False)
                except Exception:  # noqa: BLE001 — a failed benign call still produced its syscalls
                    info["call_ok"] = False

    lines: list[str] = []
    for _ in range(20):  # strace flushes -o on exit; let the torn-down child settle before we read
        try:
            with open(tracefile) as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = []
        if lines:
            break
        _time.sleep(0.05)
    try:
        if not debug:
            os.remove(tracefile)
    except OSError:
        pass

    records = parse_strace_records(lines)
    info["lines"] = len(lines)
    if debug:
        tag = call_tool_name or "BASELINE(startup)"
        print(f"[cap-debug] {tag}: {len(lines)} trace lines, events={sorted({(r.cap, r.key) for r in records}) or 'none'}")
        if call_tool_name:  # show the real socket/connect line format so the net regex can be verified
            net = [ln for ln in lines if ("socket(" in ln or "connect(" in ln or "AF_INET" in ln)][:6]
            for ln in net:
                print(f"[cap-debug]     net-line: {ln.strip()[:160]}")
    return records, tools_by_name, info


async def _run_traced(argv, env, call_timeout) -> list[CapRow]:
    import os
    debug = bool(os.environ.get("MCPRT_CAP_DEBUG"))
    base1, tools_by_name, info = await _trace_session(argv, env, call_timeout, None, debug)
    # a second identical startup reveals which write paths are volatile (random per launch): startup noise
    base2, _, _ = await _trace_session(argv, env, call_timeout, None, debug)
    writes = lambda recs: [r.key for r in recs if r.cap == CAP_WRITE]  # noqa: E731
    volatile = volatile_templates(writes(base1), writes(base2))
    startup = base1 + base2
    baseline = {(r.cap, r.key if r.cap == CAP_WRITE else r.detail) for r in startup}
    grants = launch_grants(argv, env, info["server_name"], runtime=[r.detail for r in startup if r.cap == CAP_EXEC])
    rows: list[CapRow] = []
    for name, tool in tools_by_name.items():
        records, _, tinfo = await _trace_session(argv, env, call_timeout, name, debug)
        if not tinfo["lines"]:               # nothing came back from the sensor: we saw neither good nor bad
            rows.append(CapRow(name, "", "sandbox_unobservable", "", "no trace was captured for this call",
                               tuple(sorted(declared_caps(tool)))))
            continue
        new = novel_records(records, baseline, volatile, grants.sensitive, grants.shared)   # ONLY when this tool runs
        if debug:
            print(f"[cap-debug]   {name}: new-vs-baseline = {sorted({(r.cap, r.key) for r in new}) or 'none'}")
        rows += judge(tool, new, grants, call_ok=tinfo["call_ok"] is not False)
    return rows


def main(argv=None) -> int:
    import argparse
    import shlex
    p = argparse.ArgumentParser(prog="mcp-rt hunt-cap",
                                description="MCP-00 Leg 1: hunt undeclared-capability (MCP-CAP) gaps")
    p.add_argument("--target-stdio", help='launch command, e.g. "npx -y some-mcp-server /tmp/dir"')
    p.add_argument("--record", action="store_true",
                   help="persist any hypotheses to the ledger (hypotheses table — leads, never findings)")
    p.add_argument("--selftest", action="store_true", help="run the pure-core self-check and exit")
    args = p.parse_args(argv)

    if args.selftest or not args.target_stdio:
        _selftest()
        return 0
    if not strace_available():
        print("INCONCLUSIVE — strace not found (install it: `sudo apt install strace`). "
              "MCP-CAP needs the syscall sensor; refusing to report a false CLEAN.")
        return 2
    status, hyps = run_cap_hunt(shlex.split(args.target_stdio))
    if status != "OK":
        print(f"{status} — could not observe the target under strace (launch/handshake failed).")
        return 2
    if hyps and args.record:
        _record(args.target_stdio, hyps)
    if not hyps:
        print("No undeclared-capability gaps observed (every tool stayed within its declared caps). "
              "A clean MCP-CAP hunt — not proof of total safety, just that no tool exceeded its contract.")
        return 0
    print(f"{len(hyps)} MCP-CAP hypothesis(es) — LEADS, not findings (confirm before disclosing):\n")
    for h in hyps:
        print(f"  • [{h.tool}] {h.observation}")
        print(f"      confirm: {h.confirm_plan}\n")
    if args.record:
        print(f"recorded {len(hyps)} lead(s) to the ledger (hypotheses table) — review with `mcp-rt stats`.")
    return 1


def _record(target_stdio: str, hyps: list[Hypothesis]) -> None:
    """Persist hunt leads to the ledger: idempotent target row + hypotheses (never a finding count)."""
    from .findings_db import DB
    from .report import _target_name
    db = DB()
    tid = db.add_target(name=_target_name(target_stdio), install_cmd=target_stdio, source="hunt-cap")
    record_hypotheses(db, tid, hyps)
    db.close()


# ---- runnable self-check (ponytail: fire AND stay quiet) ----------------------------------
def _selftest():
    class T:  # minimal tool stub
        def __init__(self, name, desc, props=None):
            self.name, self.description = name, desc
            self.inputSchema = {"properties": props or {}}

    # 1) a "read a file" tool that secretly opens a socket -> MUST fire (network not declared)
    reader = T("read_note", "Read the contents of a note file", {"path": {"type": "string"}})
    assert CAP_NETWORK not in declared_caps(reader)
    obs = parse_strace_caps(['123.0 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=...}, 16)'])
    gaps = classify_gaps(reader.name, declared_caps(reader), obs)
    assert len(gaps) == 1 and gaps[0].caps_observed == [CAP_NETWORK], gaps

    # 2) a fetch tool that opens a socket -> MUST stay quiet (network IS declared)
    fetcher = T("fetch_url", "Fetch the contents of a URL over HTTP", {"url": {"type": "string"}})
    assert CAP_NETWORK in declared_caps(fetcher)
    assert classify_gaps(fetcher.name, declared_caps(fetcher), obs) == []

    # 3) local IPC + device writes + reads are NOT capabilities -> stay quiet
    noise = parse_strace_caps([
        'connect(3, {sa_family=AF_UNIX, sun_path="/run/x.sock"}, 110)',
        'openat(AT_FDCWD, "/dev/null", O_WRONLY) = 4',
        'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 5',
    ])
    assert noise == set(), noise

    # 4) a real file write outside device paths -> write fires for a read-only-declared tool
    w = parse_strace_caps(['openat(AT_FDCWD, "/home/u/stolen.txt", O_WRONLY|O_CREAT, 0644) = 6'])
    assert w == {CAP_WRITE}
    assert len(classify_gaps("read_note", {CAP_READ}, w)) == 1
    print("hunt_cap selftest OK")


if __name__ == "__main__":
    import sys
    sys.exit(main())
