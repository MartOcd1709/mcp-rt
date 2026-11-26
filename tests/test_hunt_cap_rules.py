"""MCP-CAP rules, as pure functions (no tracing): what a tool declares, how a trace line is read, what counts as
startup noise, and how one traced action is judged. The live battery (test_hunt_cap_battery.py) proves the same
rules on real traces; these pin the edges that are awkward to stage with a real process."""
from types import SimpleNamespace

from hunt.hunt_cap import (CAP_EXEC, CAP_NETWORK, CAP_WRITE, LEAD, Grants, Record, declared_caps, hypothesis_of,
                           judge, launch_grants, novel_records, parse_strace_records, volatile_templates)
from hunt.probes import SUSPECTED, verdict_for


def _tool(name, desc="", **params):
    return SimpleNamespace(name=name, description=desc,
                           inputSchema={"type": "object", "properties": {p: {"type": "string"} for p in params}})


def _one(rows, cap):
    return next(r for r in rows if r.cap == cap)


# ---- what a tool declares: whole words, in its name or as a sentence's leading verb ---------------------------------
def test_substrings_no_longer_declare_anything():
    assert declared_caps(_tool("list_items", "Return the description of each item.")) == set()     # "script"
    assert declared_caps(_tool("show_balance", "Show the credit balance.")) == set()               # "edit"
    assert declared_caps(_tool("list_rows", "List rows.", page_size=1)) == set()                   # "page"
    assert declared_caps(_tool("show_history", "Shows the commit logs.")) == set()                 # a noun, not a verb
    assert declared_caps(_tool("compare", "Shows differences between two versions.", target=1)) == set()


def test_real_declarations_still_count():
    assert CAP_WRITE in declared_caps(_tool("t", "Saves the note."))                 # verb forms
    assert CAP_NETWORK in declared_caps(_tool("t", "This tool fetches a page."))     # filler words skipped
    assert CAP_EXEC in declared_caps(_tool("runShell", ""))                          # camelCase name
    assert CAP_NETWORK in declared_caps(_tool("t", "", endpoint=1))                  # an argument that is a URL
    assert CAP_WRITE in declared_caps(_tool("t", "Reads the file. Then writes a summary."))   # any sentence


def test_the_new_method_is_a_lead():
    assert verdict_for(LEAD) == SUSPECTED


# ---- reading a trace -------------------------------------------------------------------------------------------
def test_resolved_paths_exclusive_creates_and_failed_calls():
    recs = parse_strace_records([
        'openat(AT_FDCWD</srv/app>, "out/log.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 5</data/real/log.txt>',
        'openat(AT_FDCWD</srv/app>, "tmpx", O_RDWR|O_CREAT|O_EXCL, 0600) = 6</srv/app/tmpx>',
        'openat(AT_FDCWD</srv/app>, "gone.txt", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)',
        'mkdirat(AT_FDCWD</srv/app>, "newdir", 0777) = 0',
        'renameat(AT_FDCWD</srv/app>, "a.txt", AT_FDCWD</srv/app>, "b.txt") = 0',
        'unlink("relative.txt") = 0',
    ])
    by = {r.detail: r for r in recs}
    assert by["out/log.txt"].path == "/data/real/log.txt"            # the real file behind a link, from the trace
    assert by["tmpx"].exclusive and not by["out/log.txt"].exclusive
    assert "gone.txt" not in by                                      # a failed open wrote nothing
    assert by["newdir"].made_dir and by["newdir"].path == "/srv/app/newdir"
    assert by["a.txt"].path == "/srv/app/b.txt"                      # a rename is judged by where it lands
    assert by["relative.txt"].path == "" and by["relative.txt"].key == "relative.txt"   # cannot be resolved


# ---- startup noise ---------------------------------------------------------------------------------------------
def test_shared_folders_and_sensitive_files_are_compared_by_exact_path():
    base = {(CAP_WRITE, "/home/u/app_state.txt"), (CAP_WRITE, "/home/u/.cache/tool/a1"), (CAP_WRITE, "/tmp/boot.lock")}
    recs = [Record(CAP_WRITE, "x", "/home/u/.bashrc"), Record(CAP_WRITE, "x", "/home/u/note.txt"),
            Record(CAP_WRITE, "x", "/tmp/fixed.txt"), Record(CAP_WRITE, "x", "/home/u/.cache/tool/b2"),
            Record(CAP_WRITE, "x", "/home/u/app_state.txt")]
    new = {r.path for r in novel_records(recs, base, sensitive=frozenset({"/home/u/.bashrc"}),
                                         shared=frozenset({"/tmp", "/home/u"}))}
    assert new == {"/home/u/.bashrc", "/home/u/note.txt", "/tmp/fixed.txt"}   # cache churn + the same file: noise


def test_an_all_wildcard_startup_name_only_cancels_what_the_process_itself_created():
    vol = volatile_templates(["/tmp/k3j2h1g0"], ["/tmp/z9y8x7w6"])        # two startups, two random probe files
    probe, removed = Record(CAP_WRITE, "p", "/tmp/q1w2e3r4", exclusive=True), Record(CAP_WRITE, "p", "/tmp/q1w2e3r4")
    fixed = Record(CAP_WRITE, "f", "/tmp/fixed.txt")
    new = novel_records([probe, removed, fixed], set(), vol, shared=frozenset({"/tmp"}))
    assert new == [fixed]                                                 # its own probe is noise; a fixed name is not


# ---- judging one action ----------------------------------------------------------------------------------------
G = Grants(dirs=("/srv/repo",), files=("/srv/data/app.db",), identity="vcs-front-helperx --repository repo",
           runtime=frozenset({"python"}), sensitive=frozenset({"/home/u/.bashrc", "/srv/repo/.profile"}),
           temp="/tmp", home="/home/u")


def test_named_helper_covers_only_that_program():
    rows = judge(_tool("status"), [Record(CAP_EXEC, "/usr/bin/helperx"), Record(CAP_EXEC, "/usr/bin/otherprog")], G)
    by = {r.detail: r for r in rows}
    assert by["/usr/bin/helperx"].method == "by_design"                   # the server is a front end for it
    assert by["/usr/bin/otherprog"].method == LEAD


def test_identity_never_implies_running_the_launch_runtime_again():
    g = Grants(identity="python3 server.py", runtime=frozenset({"python"}))
    assert _one(judge(_tool("now", "Return the date."), [Record(CAP_EXEC, "/usr/bin/python3#2")], g), CAP_EXEC).method == LEAD
    said = _tool("calc", "Evaluate the formula via python.")              # the tool itself says so: that is declared
    assert _one(judge(said, [Record(CAP_EXEC, "/usr/bin/python3#2")], g), CAP_EXEC).method == "by_design"


def test_workspace_is_the_folder_or_file_passed_at_launch_and_nothing_wider():
    def verdict(path):
        return _one(judge(_tool("t", "Summarise."), [Record(CAP_WRITE, "x", path)], G), CAP_WRITE).method
    assert verdict("/srv/repo/.git/index.lock") == "by_design"
    assert verdict("/srv/data/app.db-journal") == "by_design"             # the launch file's own side file
    assert verdict("/srv/data/other.db") == LEAD                          # same folder, different file
    assert verdict("/srv/repository-evil/x") == LEAD                      # a look-alike prefix is not inside
    assert verdict("/srv/other/x") == LEAD
    assert _one(judge(_tool("t", "Summarise."), [Record(CAP_WRITE, "rel.txt", "")], G), CAP_WRITE).method == LEAD


def test_a_sensitive_file_is_never_by_design():
    writer = _tool("save_note", "Save the note.")                          # declares writing
    rows = judge(writer, [Record(CAP_WRITE, "x", "/home/u/.bashrc"), Record(CAP_WRITE, "x", "/srv/repo/.profile"),
                          Record(CAP_WRITE, "x", "/home/u/notes.txt")], G)
    by = {r.detail: r for r in rows}
    assert by["/home/u/.bashrc, /srv/repo/.profile"].method == LEAD        # even inside the launch workspace
    assert by["/home/u/notes.txt"].method == "by_design"


def test_scratch_files_and_running_from_temp():
    t = _tool("t", "Summarise.")
    own = judge(t, [Record(CAP_WRITE, "a", "/tmp/own_1", exclusive=True), Record(CAP_WRITE, "a", "/tmp/own_1"),
                    Record(CAP_WRITE, "d", "/tmp/d1", made_dir=True), Record(CAP_WRITE, "f", "/tmp/d1/inner.txt")], G)
    assert {r.method for r in own} == {"by_design"}
    assert _one(judge(t, [Record(CAP_WRITE, "f", "/tmp/fixed.txt")], G), CAP_WRITE).method == LEAD
    runner = _tool("run_job", "Run the job.")                               # declares running programs
    assert _one(judge(runner, [Record(CAP_EXEC, "/tmp/stage_1")], G), CAP_EXEC).method == LEAD


def test_network_and_the_empty_cases():
    t = _tool("t", "Summarise.")
    net = _one(judge(t, [Record(CAP_NETWORK, "inet"), Record(CAP_NETWORK, "203.0.113.7")], G), CAP_NETWORK)
    assert net.method == LEAD and net.detail == "203.0.113.7"              # the address, not "an internet socket"
    assert [r.method for r in judge(t, [], G, call_ok=True)] == ["oracle_negative"]
    assert [r.method for r in judge(t, [], G, call_ok=False)] == ["sandbox_not_exercised"]


def test_a_lead_names_its_object_and_keeps_the_old_wording():
    row = _one(judge(_tool("now", "Return the date."), [Record(CAP_EXEC, "/usr/bin/otherprog")], G), CAP_EXEC)
    h = hypothesis_of(row)
    assert "exercised undeclared capability: exec" in h.observation and "/usr/bin/otherprog" in h.observation
    assert h.cap == CAP_EXEC and h.detail == "/usr/bin/otherprog" and h.leg == "mcp-cap"


def test_launch_grants_reads_real_folders_and_files_only(tmp_path):
    ws, db = tmp_path / "ws", tmp_path / "data.db"
    ws.mkdir()
    db.write_text("x")
    g = launch_grants(["/opt/x/bin/thing-server", "--root", str(ws), f"--db={db}", "--missing", "/no/such/dir", "/"],
                      env={"HOME": str(tmp_path)}, server_name="thing")
    assert g.dirs == (str(ws),) and g.files == (str(db),)                 # no parent widening, no "/", nothing missing
    assert "thing-server" in g.identity and g.home == str(tmp_path)
    assert str(tmp_path / ".bashrc") in g.sensitive
