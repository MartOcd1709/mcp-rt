"""Knowledge graph / learning layer: record confirmed attacks, recall them for similar targets.

Only ground-truth-confirmed observations are stored; recall prioritises techniques whose tool
overlaps the target's tools, so the engine's suggestions improve from its own proven evidence.
"""
from mcp_rt import knowledge as kn


def _store(tmp_path):
    return kn.SqliteKnowledge(str(tmp_path / "kg.db"))


def test_record_and_recall_ranks_by_proof(tmp_path):
    s = _store(tmp_path)
    for _ in range(3):
        s.record("ssrf", "fetch", outcome="confirmed", cwe="CWE-918")
    s.record("path_traversal", "read_file", outcome="confirmed")
    hits = s.recall(["fetch", "list_dir"])
    assert hits[0]["technique"] == "ssrf" and hits[0]["count"] == 3     # most-proven first
    assert any(h["technique"] == "path_traversal" for h in hits)
    s.close()


def test_recall_prioritises_tool_overlap(tmp_path):
    s = _store(tmp_path)
    s.record("sql_injection", "run_query")              # 1x, matches target tool
    for _ in range(2):
        s.record("ssti", "render")                       # 2x, but no overlap with target tools
    hits = s.recall(["run_query"])
    assert hits[0]["technique"] == "sql_injection"       # overlap beats raw count
    s.close()


def test_recall_hints_text(tmp_path):
    s = _store(tmp_path)
    s.record("command_injection", "exec")
    txt = kn.recall_hints(["exec"], store=s)
    assert "command_injection" in txt and "confirmed" in txt
    assert kn.recall_hints(["nothing"], store=_store(tmp_path / "e")) == ""   # empty store -> no hint
    s.close()


def test_get_store_defaults_to_sqlite(monkeypatch, tmp_path):
    monkeypatch.delenv("MCPRT_GRAPH", raising=False)
    monkeypatch.setenv("MCPRT_KG_PATH", str(tmp_path / "k.db"))
    assert kn.get_store().name == "sqlite"
