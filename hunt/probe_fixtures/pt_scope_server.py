"""DELIBERATELY VULNERABLE path-traversal SCOPE server: folder-scope tools, list-of-paths members, links inside a
folder, importers and launch-folder boundaries. Every scenario has a must-fire twin and a must-stay-quiet twin.

    python pt_scope_server.py <scenario> [--root DIR]

The managed folder comes from PT_SCOPE_ROOT (always); passing `--root DIR` on the command line is what makes it a
launch-declared boundary. Tool and parameter names are novel and appear nowhere in hunt/probes.py.

NOT a real target. Local, offline; used only by tests/test_pt_scope.py.
"""
from __future__ import annotations

import json
import os
import sys

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

SCENARIO = sys.argv[1]
ROOT = os.path.realpath(os.environ["PT_SCOPE_ROOT"])
SEP = os.sep
server = Server("scope-lab")


def _prefix_ok(p, base=ROOT):          # the bug: a plain prefix test, so '<root>_x/...' passes
    return os.path.realpath(p).startswith(base)


def _sep_ok(p, base=ROOT):             # the fix: separator-aware
    rp = os.path.realpath(p)
    return rp == base or rp.startswith(base + SEP)


def _schema(*names, arrays=()):
    props = {n: {"type": "string"} for n in names}
    props.update({n: {"type": "array", "items": {"type": "string"}, "description": "Files to stage"} for n in arrays})
    return {"type": "object", "properties": props, "required": list(props)}


def _tools():
    base = SCENARIO.split("_")[0]
    if base == "creator":            # row 1: a folder creator and a folder-making "writer" beside a reader
        return [
            types.Tool(name="allowed_dirs", description="List the folders this lab may use.",
                       inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="create_dir", description="Create a new folder.", inputSchema={"type": "object"}),
            types.Tool(name="stash_note", description="Create a note folder at the given path and save the content "
                       "inside it.", inputSchema=_schema("path", "content")),
            types.Tool(name="peek", description="Read a file from the data folder.", inputSchema=_schema("target")),
        ]
    if base == "stage":              # row 2: stage a list of files in a workspace, shown later by a status tool
        return [
            types.Tool(name="stage", description="Stage the given files in the workspace.",
                       inputSchema=_schema("workspace", arrays=("files",))),
            types.Tool(name="staged", description="Show what is staged in the workspace.",
                       inputSchema=_schema("workspace")),
        ]
    if base == "walk":               # row 3: summarise a folder
        return [types.Tool(name="tally", description="Summarise the config files (settings.yml) in a folder.",
                           inputSchema=_schema("folder"))]
    if base == "import":             # row 4: an importer that should only read its own exports
        return [types.Tool(name="restore_context", description="Import a previously exported context from a file.",
                           inputSchema=_schema("file"))]
    if base == "launch":             # row 5: a reader bounded only by its launch folder
        return [types.Tool(name="look", description="Read a file from the data folder.", inputSchema=_schema("target"))]
    raise SystemExit(f"unknown scenario {SCENARIO}")


def _work(name, a):
    safe = SCENARIO.endswith("_safe")
    ok = _sep_ok if safe else _prefix_ok
    if name == "allowed_dirs":
        return ROOT
    if name == "create_dir":
        os.makedirs(a.get("path", ""), exist_ok=True)
        return "created"
    if name == "stash_note":
        os.makedirs(a["path"], exist_ok=True)
        with open(os.path.join(a["path"], "note.txt"), "w") as fh:
            fh.write(a["content"])
        return "stashed"
    if name in ("peek", "look"):
        return open(a["target"]).read() if ok(a["target"]) else "denied"
    if name in ("stage", "staged"):
        ws = os.path.realpath(a["workspace"])
        if not _sep_ok(ws):
            return "error: workspace is not this lab's workspace"
        index = os.path.join(ws, ".staged")
        if name == "staged":
            return open(index).read() if os.path.exists(index) else "nothing staged"
        added = 0
        for f in a.get("files", []):
            p = f if os.path.isabs(f) else os.path.join(ws, f)
            if not ok(p, ws):
                return f"error: {f} is outside the workspace"
            with open(index, "a") as fh:
                fh.write(f"== {f}\n{open(p).read()}\n")
            added += 1
        return f"staged {added} file(s)"
    if name == "tally":
        folder = a["folder"]
        lines = []
        for n in sorted(os.listdir(folder)):
            p = os.path.join(folder, n)
            if os.path.islink(p):
                if SCENARIO == "walk_skip":
                    continue
                if SCENARIO == "walk_real" and not _sep_ok(p, os.path.realpath(folder)):
                    continue
                if SCENARIO == "walk_list":
                    lines.append(f"{n}: link")
                    continue
            if os.path.isfile(p):
                lines.append(f"{n}: {len(open(p).read().splitlines())} lines")
        return "\n".join(lines) or "empty folder"
    if name == "restore_context":
        f = a["file"]
        if safe:
            if not _sep_ok(f):
                return "error: invalid context file"
            try:
                json.load(open(f))
                return "imported"
            except Exception:  # noqa: BLE001
                return "error: invalid context file"
        data = open(f).read()
        try:
            json.loads(data)
            return "imported"
        except ValueError:
            return f"error: invalid context: {data[:200]}"       # the bug: echoes what it read (CWE-209)
    return "unknown tool"


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return _tools()


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        out = await anyio.to_thread.run_sync(lambda: _work(name, arguments or {}))
    except Exception as exc:  # noqa: BLE001
        out = f"error: {exc}"
    return [types.TextContent(type="text", text=str(out)[:4096])]


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="scope-lab", server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(), experimental_capabilities={})))


if __name__ == "__main__":
    anyio.run(_amain)
