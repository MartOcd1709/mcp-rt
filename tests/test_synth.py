"""Valid-input synthesis: schema precedence, parameter semantics, context harvest, and error-guided repair.
Every value must be VALID-shaped so a real tool executes; the attack payload still reaches its own parameter."""
import os
import tempfile

from hunt import synth
from hunt.synth import Context, value


def ctx(**kw):
    kw.setdefault("base_dir", tempfile.mkdtemp())
    return Context(**kw)


# ---- schema is authoritative, in order ----
def test_const_enum_default_example_win_over_semantics():
    c = ctx(url="http://seal/")
    assert value("url", {"const": "fixed"}, c) == "fixed"                      # const wins even for a url param
    assert value("mode", {"type": "string", "enum": ["preview", "export"]}, c) == "preview"
    assert value("url", {"type": "string", "default": "http://d/"}, c) == "http://d/"
    assert value("url", {"type": "string", "examples": ["http://e/"]}, c) == "http://e/"


def test_format_drives_the_value():
    c = ctx()
    assert value("x", {"type": "string", "format": "email"}, c) == "dev@example.com"
    assert value("x", {"type": "string", "format": "date-time"}, c).startswith("2026-01-01")
    assert value("x", {"type": "string", "format": "uri"}, c).startswith("http")


# ---- semantics: a valid instance per kind ----
def test_timezone_url_email_host_number():
    c = ctx(url="http://127.0.0.1:9999/r")
    assert value("timezone", {"type": "string"}, c) == "UTC"
    assert value("target_timezone", {"type": "string", "description": "the zone"}, c) == "UTC"
    assert value("url", {"type": "string"}, c) == "http://127.0.0.1:9999/r"
    assert value("to", {"type": "string", "description": "the webhook endpoint"}, c) == "http://127.0.0.1:9999/r"
    assert "@" in value("owner_email", {"type": "string"}, c)
    assert value("port", {"type": "integer"}, c) == 8080
    assert value("count", {"type": "integer", "minimum": 5, "maximum": 9}, c) == 7


def test_paths_and_repo_come_from_context():
    base = tempfile.mkdtemp()
    repo = os.path.join(base, "project.git")
    os.makedirs(repo)
    c = Context(base_dir=base, paths=[repo, base])
    assert value("repo_path", {"type": "string"}, c) == repo
    assert value("repository", {"type": "string", "description": "git repository"}, c) == repo
    # a file param with no harvested file -> a real file the harness created
    fp = value("path", {"type": "string", "description": "file to read"}, c)
    assert os.path.isfile(fp)
    # a directory param -> a real directory
    dp = value("path", {"type": "string", "description": "the directory"}, c)
    assert os.path.isdir(dp)


def test_sql_object_and_branch_use_harvested_strings():
    c = ctx(strings=["customers", "orders", "main"])
    assert value("table_name", {"type": "string"}, c) == "customers"
    assert value("branch", {"type": "string"}, c) == "main"
    assert value("table", {"type": "string"}, ctx()) == "data"           # fallback when nothing harvested


# ---- the attacked parameter carries the payload; everything else stays valid ----
def test_payload_carried_only_in_the_target_param():
    c = ctx(url="http://seal/")
    schema = {"type": "object", "properties": {
        "repo_path": {"type": "string", "description": "repository"}, "message": {"type": "string"}},
        "required": ["repo_path", "message"]}
    props = schema["properties"]
    args = {}
    for n, s in props.items():
        args[n] = value(n, s, Context(base_dir="/srv/app", paths=["/srv/app"]),
                        want_string_payload="PAYLOAD-HERE" if n == "message" else None)
    assert args["message"] == "PAYLOAD-HERE"       # the attack lands in its param
    assert args["repo_path"] == "/srv/app"         # the carrier param is valid so the tool runs
    # array param carries the payload as its one element
    assert value("cmd", {"type": "array", "items": {"type": "string"}}, c, want_string_payload="P") == ["P"]


def test_object_and_array_recurse():
    c = ctx()
    v = value("opts", {"type": "object", "properties": {"n": {"type": "integer"}, "tz": {"type": "string"}},
                       "required": ["n", "tz"]}, c)
    assert v == {"n": 1, "tz": "UTC"}
    assert value("items", {"type": "array", "items": {"type": "integer"}}, c) == [1]


# ---- error-guided repair ----
def test_repair_parses_the_valid_options_from_the_error():
    opts = synth._enum_from_error("Error: mode must be one of [preview, export, raw]")
    assert opts == ["preview", "export", "raw"]
    assert synth._enum_from_error("expected json|yaml|toml") == ["json", "yaml", "toml"]
    args = {"mode": "bad"}
    fixed = synth.repair(args, {"properties": {"mode": {"type": "string"}}}, ctx(), "mode must be one of [a, b]")
    assert fixed == {"mode": "a"}


def test_repair_fixes_timezone_url_and_path():
    props = {"properties": {"tz": {"type": "string", "description": "timezone"},
                            "u": {"type": "string", "description": "url"},
                            "p": {"type": "string", "description": "repo path"}}}
    c = Context(base_dir="/b", url="http://seal/", paths=["/srv/repo"])
    assert synth.repair({"tz": "bad"}, props, c, "Invalid timezone: 'bad'")["tz"] == "UTC"
    assert synth.repair({"u": "bad"}, props, c, "Input should be a valid URL")["u"] == "http://seal/"
    r = synth.repair({"p": "bad"}, props, c, "Repository path 'bad' is outside the allowed repository")
    assert r["p"] in ("/srv/repo", "/b") or r["p"].startswith("/")
    assert synth.repair({"x": "y"}, {"properties": {"x": {"type": "string"}}}, c, "unrelated error") is None


def test_repair_uses_a_path_quoted_in_the_error():
    props = {"properties": {"p": {"type": "string", "description": "path"}}}
    r = synth.repair({"p": "x"}, props, ctx(), "path must be under /data/allowed")
    assert r["p"] == "/data/allowed"


# ---- context harvest ----
def test_harvest_argv_extracts_real_paths_and_their_dirs():
    paths = synth.harvest_argv(["/opt/venv/bin/mcp-server-git", "--repository", "/srv/repo"])
    assert "/srv/repo" in paths
    paths2 = synth.harvest_argv(["mcp-server-sqlite", "--db-path", "/srv/analytics/app.db"])
    assert "/srv/analytics/app.db" in paths2 and "/srv/analytics" in paths2   # the db's directory too
    assert synth.harvest_argv(["python3", "/opt/x.py"]) == []                 # the script itself is not a target path


def test_harvest_strings_pulls_identifiers_skips_noise():
    out = synth.harvest_strings("tables: customers, orders (2 rows). error and null values")
    assert "customers" in out and "orders" in out
    assert "error" not in out and "null" not in out and "and" not in out
