"""path_traversal scope battery: folder-scope tools, list-of-paths members seen through an observer, links inside a
probe-built folder, importers, and launch-folder boundaries. Each row has a must-fire and a must-stay-quiet twin on
hunt/probe_fixtures/pt_scope_server.py, whose tool and parameter names appear nowhere in hunt/probes.py."""
import ast
import asyncio
import json
import os
import re
import sys
from pathlib import Path

import pytest

from hunt import probes as P
from hunt import synth

_FIXTURE = Path(P.__file__).resolve().parent / "probe_fixtures" / "pt_scope_server.py"
_NOVEL = ("create_dir", "stash_note", "peek", "staged", "tally", "restore_context", "scope-lab", "settings.yml")
_ROSTER = Path(os.environ.get("MCPRT_REAL_ROSTER", "/home/ved/Desktop/mcp-rt-console/lab/real.json"))


def _tree(root: Path) -> dict:
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() and not p.is_symlink() else "dir")
            for p in sorted(root.rglob("*"))}


def _scan(tmp_path, scenario, launch="", write_into_root=False):
    srv = tmp_path / "srv"
    root = srv / "repo"
    root.mkdir(parents=True)
    (root / "readme.txt").write_text("in-root file")
    before = _tree(root)
    argv = [sys.executable, str(_FIXTURE), scenario]
    if launch == "root":
        argv += ["--root", str(root)]
    elif launch == "file":
        argv += ["--db-path", str(root / "readme.txt")]
    old = P._ALLOW_WRITE_INTO_ROOT
    P._ALLOW_WRITE_INTO_ROOT = write_into_root
    try:
        rows = asyncio.run(P.scan_target(argv, env={**os.environ, "PT_SCOPE_ROOT": str(root)},
                                         probes=[P.probe_path_traversal]))
    finally:
        P._ALLOW_WRITE_INTO_ROOT = old
    assert not any(r.confirmation_method == "error" for r in rows), [(r.tool, r.rationale) for r in rows]
    unchanged = _tree(root) == before and sorted(os.listdir(srv)) == ["repo"]
    return {r.tool: r for r in rows}, unchanged


# ---- row 1: a folder creator beside the reader no longer aborts the probe, and leaves nothing behind
def test_row1_folder_creator_does_not_abort_and_reader_leak_fires(tmp_path):
    rows, unchanged = _scan(tmp_path, "creator")
    assert rows["peek"].verdict == P.VULNERABLE and "sibling-prefix" in rows["peek"].rationale
    assert rows["stash_note"].verdict == P.INCONCLUSIVE       # makes a folder where a file was expected
    assert unchanged, "control files or folders were left in the root or beside it"


def test_row1_confined_reader_stays_clean(tmp_path):
    rows, unchanged = _scan(tmp_path, "creator_safe")
    assert rows["peek"].verdict == P.CLEAN
    assert unchanged


# ---- row 2: a file outside the folder passed as a list member, seen through the status tool
def test_row2_list_member_escape_seen_through_observer(tmp_path):
    rows, unchanged = _scan(tmp_path, "stage", "root", write_into_root=True)
    r = rows["stage"]
    assert (r.confirmation_method, r.verdict) == ("oracle", P.VULNERABLE) and "observer" in r.evidence
    assert unchanged, "write-into-root variant did not restore what it touched"


def test_row2_separator_aware_stager_stays_clean(tmp_path):
    rows, unchanged = _scan(tmp_path, "stage_safe", "root", write_into_root=True)
    assert rows["stage"].verdict == P.CLEAN
    assert unchanged


def test_row2_without_write_into_root_mode_is_inconclusive_and_untouched(tmp_path):
    rows, unchanged = _scan(tmp_path, "stage", "root", write_into_root=False)
    assert (rows["stage"].confirmation_method, rows["stage"].verdict) == ("write_into_root_off", P.INCONCLUSIVE)
    assert unchanged


# ---- row 3: a link inside a probe-built folder
@pytest.mark.parametrize("scenario,method", [("walk", "differential"), ("walk_skip", "oracle_negative"),
                                             ("walk_real", "oracle_negative"), ("walk_list", "link_listed_unread")])
def test_row3_scope_folder_link(tmp_path, scenario, method):
    rows, unchanged = _scan(tmp_path, scenario)
    r = rows["tally"]
    assert r.confirmation_method == method, (r.confirmation_method, r.rationale)
    assert unchanged


def test_row3_verdicts_follow_the_spine():
    assert P.verdict_for("differential") == P.VULNERABLE
    assert P.verdict_for("link_listed_unread") == P.SUSPECTED
    assert P.verdict_for("unscoped_leak") == P.SUSPECTED
    assert P.verdict_for("write_into_root_off") == P.INCONCLUSIVE


# ---- row 4: an importer that echoes a file it should not read
def test_row4_importer_leak_with_known_root_is_proven(tmp_path):
    rows, _ = _scan(tmp_path, "import", "root")
    assert (rows["restore_context"].confirmation_method, rows["restore_context"].verdict) == ("oracle", P.VULNERABLE)


def test_row4_confined_importer_is_not_flagged(tmp_path):
    rows, _ = _scan(tmp_path, "import_safe", "root")
    assert rows["restore_context"].verdict in (P.CLEAN, P.INCONCLUSIVE)


def test_row4_importer_leak_without_root_is_a_lead(tmp_path):
    rows, _ = _scan(tmp_path, "import")
    assert (rows["restore_context"].confirmation_method, rows["restore_context"].verdict) == \
        ("unscoped_leak", P.SUSPECTED)


# ---- row 5: the boundary from launch folders
def test_row5_prefix_reader_escapes_its_launch_folder(tmp_path):
    rows, unchanged = _scan(tmp_path, "launch", "root")
    assert rows["look"].verdict == P.VULNERABLE and "sibling-prefix" in rows["look"].rationale
    assert unchanged


def test_row5_separator_aware_reader_is_clean(tmp_path):
    rows, _ = _scan(tmp_path, "launch_safe", "root")
    assert rows["look"].verdict == P.CLEAN


def test_row5_folder_of_a_file_argument_is_not_a_root(tmp_path):
    rows, _ = _scan(tmp_path, "launch", "file")       # launched with a file inside the folder, not the folder
    assert rows["look"].verdict != P.VULNERABLE


def test_row5_parent_folders_of_launch_arguments_are_not_roots(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "app.db").write_text("")
    (tmp_path / "repo").mkdir()
    argv = ["/usr/bin/server", "--db-path", str(tmp_path / "data" / "app.db"), "--repository", str(tmp_path / "repo")]
    old = P._SYNTH_CTX
    P._SYNTH_CTX = synth.Context(paths=synth.harvest_argv(argv), launch=synth.harvest_argv(argv, parents=False))
    try:
        roots = P._launch_roots()
    finally:
        P._SYNTH_CTX = old
    assert str(tmp_path / "data") in synth.harvest_argv(argv)       # synth still offers the parent as a value
    assert roots == [os.path.realpath(tmp_path / "repo")]          # but only the folder argument is a root


# ---- leads reach the report like other classes' leads
def test_path_traversal_lead_reaches_the_report(monkeypatch):
    from hunt import report

    async def fake_scan(argv, env=None, surface=None):
        surface.update(tools=[], resources=[])
        return [P.ProbeResult("path_traversal", "some_tool", "unscoped_leak", rationale="lead")]

    class Tok:
        verdict, passthrough, transcript, rationale = P.NOT_APPLICABLE, None, [], ""

    async def fake_tok(argv, env=None):
        return Tok()

    monkeypatch.setattr(report, "scan_target", fake_scan)
    monkeypatch.setattr(report, "probe_token_passthrough", fake_tok)
    rep = asyncio.run(report.run_full_scan(["/nonexistent/server"]))
    assert [s["cls"] for s in rep["suspected"]] == ["path_traversal"] and not rep["findings"]
    status = {c["id"]: c["status"] for c in rep["compliance"]}
    assert all(status[c] == "SUSPECTED" for c in report.lead_controls("path_traversal"))


# ---- the dynamic gate: no fixture name and no real-roster name in the probe's code
def _code_strings() -> list[str]:
    tree = ast.parse(Path(P.__file__).read_text())
    docs = {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body
            and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs:
            out.append(n.value.lower())
        elif isinstance(n, ast.Name):
            out.append(n.id.lower())
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(n.name.lower())
    return out


def test_dynamic_gate_no_fixture_names_in_probe():
    src = Path(P.__file__).read_text()
    for n in _NOVEL:
        assert n not in src, f"probes.py names a fixture tool ({n}) — not dynamic"


def _roster_names(roster: dict) -> set[str]:
    names = set()
    for client in roster.get("clients", []):
        for machine in client.get("machines", []):
            for key, s in machine.get("servers", {}).items():
                if "-" in key:
                    names.add(key)
                pkg = s.get("pip") or s.get("npm") or ""
                names.add(re.split(r"[=@\[]", pkg.split("/")[-1].lstrip("@"))[0])
                names.update(Path(a).name for a in s.get("command", [])[:1])
                names.update(a for a in s.get("command", []) if a.startswith("--"))
                bench = s.get("bench") or {}
                names.update(bench.get("advisories", []))
                names.update(re.findall(r"\b[a-z]+_[a-z_]+\b", bench.get("note", "")))
    return {n.lower() for n in names if len(n) > 3}


@pytest.mark.skipif(not _ROSTER.is_file(), reason="real roster not on this machine (set MCPRT_REAL_ROSTER)")
def test_dynamic_gate_no_real_roster_name_in_probe_code():
    names = _roster_names(json.loads(_ROSTER.read_text()))
    assert "--repository" in names and any(n.startswith("cve-") for n in names)   # the roster really was read
    hits = sorted({n for n in names for s in _code_strings() if n in s})
    assert not hits, f"probes.py code names real-roster servers/tools/flags/advisories: {hits}"
