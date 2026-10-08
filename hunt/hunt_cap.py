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

import re
import shutil
from dataclasses import dataclass, field

from .probes import _URL_PARAM, _schema

CAP_NETWORK, CAP_WRITE, CAP_EXEC, CAP_READ = "network", "write", "exec", "read"

# Declaration vocabulary is deliberately GENEROUS (broader than the probes' narrow write/fetch regexes):
# declaring a capability can only SUPPRESS a hypothesis, never create one, so erring wide protects the
# zero-FP guarantee. A tool named move_file/delete_entry/upload clearly declares its side effect; only a
# tool that does something NO word in its name or description hints at should ever surface a gap.
_DECL_NET = re.compile(
    r"fetch|http|url|uri|\bweb\b|request|download|upload|crawl|scrape|curl|\bapi\b|endpoint|webhook|"
    r"remote|connect|\bsend\b|\bpost\b|\bsync\b|publish|notify|email|slack|\bdns\b|\bhost\b", re.I)
_DECL_WRITE = re.compile(
    r"write|create|save|edit|append|\bput\b|modify|\bmove\b|rename|delete|remove|unlink|mkdir|\bcopy\b|"
    r"upload|store|insert|update|patch|\btouch\b|\bmount\b|\bset\b|persist|commit|export|download", re.I)
_DECL_EXEC = re.compile(
    r"\brun\b|execute|\bexec\b|shell|command|spawn|subprocess|process|script|eval|compile|interpreter|"
    r"\bpython\b|\bbash\b|\bsh\b|invoke|launch|\bbuild\b|\bgit\b|\bnpm\b|\bpip\b|terminal", re.I)


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


# ---- declared capability (what the tool's schema/description advertises) -----------------
def declared_caps(tool) -> set[str]:
    """Capabilities a tool openly advertises. Used ONLY to suppress by-design behaviour — a tool
    that declares network and makes a socket is not a gap. Conservative: when unsure, declare MORE
    (declaring a cap can only suppress a hypothesis, never create one) so we never over-flag."""
    text = f"{tool.name} {getattr(tool, 'description', '') or ''}"
    params = " ".join((_schema(tool).get("properties") or {}).keys())
    caps: set[str] = set()
    if _DECL_NET.search(text) or _URL_PARAM.search(params):
        caps.add(CAP_NETWORK)
    if _DECL_WRITE.search(text):
        caps.add(CAP_WRITE)
    if _DECL_EXEC.search(text):
        caps.add(CAP_EXEC)
    return caps


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
_RE_BENIGN_WRITE_PATH = re.compile(r'"(/dev/|/proc/|/sys/|/tmp/\.|.*\.sock)')


_QUOTED = re.compile(r'"([^"]*)"')                 # first quoted string = path for open/exec/unlink
_INET_ADDR = re.compile(r'inet_addr\("([^"]+)"\)|sin_addr=inet_addr\("([^"]+)"\)|'
                        r'inet_pton\([^,]+,\s*"([^"]+)"')


def _first_quoted(ln: str) -> str:
    m = _QUOTED.search(ln)
    return m.group(1) if m else ""


def _inet_detail(ln: str) -> str:
    m = _INET_ADDR.search(ln)
    return (m.group(1) or m.group(2) or m.group(3)) if m else "inet"


def parse_strace_events(lines) -> set[tuple[str, str]]:
    """Reduce strace output to the set of (capability, detail) the child exercised, where detail is
    the path / address / binary. Carrying the detail lets baseline-diff cancel startup noise precisely
    (a tool's write to ~/x is kept even though python also writes __pycache__ at startup). Reads are
    never returned; local IPC and device/cache writes are excluded."""
    ev: set[tuple[str, str]] = set()
    for ln in lines:
        if _RE_EXECVE.search(ln):
            ev.add((CAP_EXEC, _first_quoted(ln)))
        if (_RE_CONNECT_INET.search(ln) or _RE_SOCKET_INET.search(ln)) and not _RE_LOCAL_SOCK.search(ln):
            ev.add((CAP_NETWORK, _inet_detail(ln)))
        if _RE_FS_MUTATE.search(ln):
            ev.add((CAP_WRITE, _first_quoted(ln)))
        elif _RE_OPEN_WRITE.search(ln):
            path = _first_quoted(ln)
            if not _RE_BENIGN_WRITE_PATH.search(ln) and "__pycache__" not in path and not path.endswith(".pyc"):
                ev.add((CAP_WRITE, path))
    return ev


def caps_from_events(events) -> set[str]:
    return {cap for cap, _ in events}


def _dirname(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else path


def novel_caps(tool_events, baseline) -> set[str]:
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
            if _dirname(detail) not in base_write_dirs:
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
STRACE_ARGV = ["strace", "-f", "-qq", "-e",
               "trace=network,openat,execve,unlink,unlinkat,rename,renameat,mkdir,mkdirat"]


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
    if not strace_available():
        return ("INCONCLUSIVE", [])
    import asyncio
    try:
        return ("OK", asyncio.run(_run_traced(argv, env, call_timeout)))
    except Exception:  # noqa: BLE001 — a handshake/launch failure is INCONCLUSIVE, not a false CLEAN
        return ("INCONCLUSIVE", [])


async def _trace_session(argv, env, call_timeout, call_tool_name, debug=False):
    """Launch the target under strace, run the handshake, optionally call ONE tool, and return
    (events, tools_by_name). `call_tool_name=None` yields the startup-only baseline. Per-tool launches
    give deterministic attribution — no wall-clock windowing, no clock-alignment assumptions."""
    import os
    import tempfile
    import time as _time
    import asyncio as _asyncio
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from .probes import _build_args

    tracefile = tempfile.mktemp(prefix="mcprt_strace_", suffix=".log")
    wrapped = STRACE_ARGV + ["-o", tracefile, "--"] + list(argv)
    params = StdioServerParameters(command=wrapped[0], args=wrapped[1:], env=env or dict(os.environ))
    tools_by_name = {}
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            for t in (await session.list_tools()).tools:
                tools_by_name[t.name] = t
            if call_tool_name and call_tool_name in tools_by_name:
                try:
                    await _asyncio.wait_for(
                        session.call_tool(call_tool_name, _build_args(tools_by_name[call_tool_name], {})),
                        call_timeout)
                except Exception:  # noqa: BLE001 — a failed benign call still produced its syscalls
                    pass

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

    events = parse_strace_events(lines)
    if debug:
        tag = call_tool_name or "BASELINE(startup)"
        print(f"[cap-debug] {tag}: {len(lines)} trace lines, events={sorted(events) or 'none'}")
        if call_tool_name:  # show the real socket/connect line format so the net regex can be verified
            net = [ln for ln in lines if ("socket(" in ln or "connect(" in ln or "AF_INET" in ln)][:6]
            for ln in net:
                print(f"[cap-debug]     net-line: {ln.strip()[:160]}")
    return events, tools_by_name


async def _run_traced(argv, env, call_timeout) -> list[Hypothesis]:
    import os
    debug = bool(os.environ.get("MCPRT_CAP_DEBUG"))
    baseline, tools_by_name = await _trace_session(argv, env, call_timeout, None, debug)
    hyps: list[Hypothesis] = []
    for name, tool in tools_by_name.items():
        events, _ = await _trace_session(argv, env, call_timeout, name, debug)
        new_caps = novel_caps(events, baseline)   # capabilities that appear ONLY when this tool runs
        if debug:
            print(f"[cap-debug]   {name}: new-vs-baseline caps = {sorted(new_caps) or 'none'}")
        hyps += classify_gaps(name, declared_caps(tool), new_caps)
    return hyps


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
