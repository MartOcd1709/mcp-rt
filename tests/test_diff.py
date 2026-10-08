"""M3: re-test/diff — RESOLVED/NEW/UNCHANGED classification + version-agnostic prior lookup."""
from hunt.diff import _base, classify, prior_vuln_classes
from hunt.findings_db import DB


def test_base_strips_version():
    assert _base("yl-mcp-git-server@1.1.4") == "yl-mcp-git-server"
    assert _base("@scope/pkg@0.3.2") == "@scope/pkg"      # scoped name keeps its leading @
    assert _base("plain-pkg") == "plain-pkg"


def test_classify_delta():
    d = classify({"command_injection", "sql_injection"}, {"sql_injection", "ssrf"})
    assert d["resolved"] == ["command_injection"]
    assert d["new"] == ["ssrf"]
    assert d["unchanged"] == ["sql_injection"]


def test_prior_lookup_is_version_agnostic(tmp_path):
    db = DB(tmp_path / "t.db")
    tid = db.add_target(name="demo-mcp@1.0.0", install_cmd="npx -y demo-mcp@1.0.0")
    db.add_scan(tid, mode="report:command_injection", verdict="VULNERABLE")
    db.add_scan(tid, mode="report:path_traversal", verdict="VULNERABLE")
    # re-testing v1.0.1 must find v1.0.0's findings by base name
    prior, name = prior_vuln_classes(db, "npx -y demo-mcp@1.0.1")
    db.close()
    # _base only strips a trailing @ver; the lookup matches targets by base package name
    assert name == "demo-mcp@1.0.0"
    assert prior == {"command_injection", "path_traversal"}
