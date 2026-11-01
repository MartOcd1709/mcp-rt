"""#27 path_traversal by-design / boundary discrimination (companion to #22 SSRF).

The discriminator is "is a boundary DECLARED (advertised allowed-dirs root)?", NOT "does a naive path
succeed?". A dynamic, name-free battery pins every branch of the corrected matrix on synthetic servers
(random tool names — nothing here is baked into the probe source):

  ADVERTISED ROOT (declared boundary):
    any out-of-root leak (plain=unenforced OR crafted=bypass)  -> VULNERABLE (oracle)
    no leak + in-root positive control passes                  -> CLEAN (refusal/oracle_negative)
    no leak + positive control fails                           -> INCONCLUSIVE (positive_control_unverified)
  NO ADVERTISED ROOT (no declared boundary):
    naive plain leak                                           -> by_design (DC allowedDirectories=[] FP)
    crafted-only leak (SUBCASE-1)                              -> VULNERABLE (intended-but-bypassable filter)
    no leak + relative in-bounds round-trip control passes     -> CLEAN  (SUBCASE-2)
    no leak + control can't be constructed / fails             -> INCONCLUSIVE (SUBCASE-2)
"""
import asyncio
import secrets
import sys

import pytest

from hunt import probes
from hunt.probes import probe_path_traversal, scan_target

# A generated filesystem-style MCP server. list_allowed_directories advertises a root ONLY in the
# advertised-root modes (conventional name — that is how the probe discovers the boundary). The
# reader/writer tool names are RANDOM; the probe selects them by declared purpose, never by name.
SERVER = '''import asyncio, os, urllib.parse
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

ROOT = os.path.realpath(__ROOT__)
MODE = __MODE__
RD = __RD__
WR = __WR__
ADVERTISED = MODE in ("vuln_decode", "safe", "broken")     # these modes advertise a root
srv = Server("ptgen")


def _resolve(raw):
    return raw if os.path.isabs(raw) else os.path.join(ROOT, raw)


def _in_root(p):
    rp, root = os.path.normpath(p), os.path.normpath(ROOT)
    return rp == root or rp.startswith(root + os.sep)


def _cwd_denied(dec):                      # cwd-confined guard: reject absolute / parent-escape
    return dec.startswith("/") or ".." in dec or "\\\\" in dec


@srv.list_tools()
async def lt():
    return [
        types.Tool(name="list_allowed_directories",
                   description="List the directories this server is allowed to access.",
                   inputSchema={"type": "object", "properties": {}}),
        types.Tool(name=RD, description="Read the contents of a file at the given path.",
                   inputSchema={"type": "object", "properties": {"path": {"type": "string"}},
                                "required": ["path"]}),
        types.Tool(name=WR, description="Write content to a file at the given path.",
                   inputSchema={"type": "object",
                                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                                "required": ["path", "content"]}),
    ]


def _read(raw):
    if MODE == "noboundary":
        return open(_resolve(raw)).read()                         # no boundary: read anything
    if MODE == "broken":
        return "ok"                                               # never reads -> oracle unverifiable
    if MODE == "subcase2_incon":
        return "denied"                                           # refuses everything, incl. the control
    if MODE == "vuln_decode":
        if not _in_root(_resolve(raw)):                           # check the RAW (real ../ normalised)...
            raise PermissionError("Security violation: path outside allowed roots")
        return open(_resolve(urllib.parse.unquote(raw))).read()   # ...decode AFTER the check (the bug)
    if MODE == "subcase1":
        if _cwd_denied(raw):                                      # literal check BEFORE decode (the bug)
            return "denied"
        return open(urllib.parse.unquote(raw)).read()             # decode after -> cwd-relative escape
    if MODE == "subcase2_clean":
        dec = urllib.parse.unquote(raw)                           # decode BEFORE check -> safe, cwd-confined
        if _cwd_denied(dec):
            return "denied"
        return open(dec).read()
    target = _resolve(urllib.parse.unquote(raw))                  # safe advertised-root: decode+check in-root
    if not _in_root(target):
        raise PermissionError("Security violation: path outside allowed roots")
    return open(target).read()


def _write(raw, content):
    if MODE == "noboundary":
        target = _resolve(raw)
    elif MODE == "subcase2_incon":
        return "denied"
    elif MODE in ("subcase1", "subcase2_clean"):
        dec = urllib.parse.unquote(raw)                           # cwd-confined writer
        if _cwd_denied(dec):
            return "denied"
        target = dec
    else:
        target = _resolve(urllib.parse.unquote(raw))              # advertised-root confined writer
        if not _in_root(target):
            raise PermissionError("Security violation: path outside allowed roots")
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    with open(target, "w") as f:
        f.write(content)
    return "written"


@srv.call_tool()
async def ct(name, args):
    a = args or {}
    try:
        if name == "list_allowed_directories":
            out = ROOT if ADVERTISED else ""
        elif name == RD:
            out = _read(str(a.get("path", "")))
        elif name == WR:
            out = _write(str(a.get("path", "")), str(a.get("content", "")))
        else:
            out = "unknown"
    except Exception as e:
        out = "err: " + str(e)[:120]
    return [types.TextContent(type="text", text=str(out)[:2000])]


async def main():
    async with stdio_server() as (r, w):
        await srv.run(r, w, srv.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
'''

# (mode, tool-key, expected confirmation_method, expected verdict)
CASES = [
    # advertised root (declared boundary)
    ("noboundary", "WR", "by_design", "CLEAN"),                       # DC write_file @ allowedDirectories=[] FP
    ("noboundary", "RD", "by_design", "CLEAN"),                       # unrestricted read is the contract
    ("vuln_decode", "RD", "oracle", "VULNERABLE"),                   # advertised root + crafted escape
    ("safe", "RD", "refusal", "CLEAN"),                             # boundary holds against every vector
    ("broken", "RD", "positive_control_unverified", "INCONCLUSIVE"),  # advertised root, oracle unverifiable
    # no advertised root (no declared boundary)
    ("subcase1", "RD", "oracle", "VULNERABLE"),                      # SUBCASE-1: plain denied, crafted leaks
    ("subcase2_clean", "RD", "oracle_negative", "CLEAN"),            # SUBCASE-2: round-trip control passes
    ("subcase2_incon", "RD", "positive_control_unverified", "INCONCLUSIVE"),  # SUBCASE-2: control can't pass
]


def _run(mode, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    rd, wr = "rd_" + secrets.token_hex(3), "wr_" + secrets.token_hex(3)
    src = (SERVER.replace("__ROOT__", repr(str(root))).replace("__MODE__", repr(mode))
                 .replace("__RD__", repr(rd)).replace("__WR__", repr(wr)))
    script = tmp_path / "pt_server.py"
    script.write_text(src)
    rows = asyncio.run(scan_target([sys.executable, str(script)], probes=[probe_path_traversal]))
    return {"RD": rd, "WR": wr}, rows


@pytest.mark.parametrize("mode,key,method,verdict", CASES, ids=[f"{m}-{k}" for m, k, _, _ in CASES])
def test_boundary_discrimination(mode, key, method, verdict, tmp_path):
    names, rows = _run(mode, tmp_path)
    tool = names[key]
    mine = [r for r in rows if r.tool == tool]
    assert mine, f"no path_traversal row for {tool} ({mode}); got {[(r.tool, r.confirmation_method) for r in rows]}"
    r = mine[0]
    assert (r.confirmation_method, r.verdict) == (method, verdict), \
        (mode, key, r.confirmation_method, r.verdict, r.rationale)


def test_name_free_no_generated_name_leaks_into_probe_source():
    src = open(probes.__file__).read()
    for _ in range(5):
        assert ("rd_" + secrets.token_hex(3)) not in src
        assert ("wr_" + secrets.token_hex(3)) not in src
