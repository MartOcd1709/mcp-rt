"""Knowledge graph / learning layer — the engine learns from every confirmed attack.

When a technique is CONFIRMED by ground truth against a target, we record it as knowledge
(technique → tool → outcome). Before the next assessment, `recall()` pulls the most relevant past
wins for a target with similar tools, and those hints are fed into the model's prompt — so the
engine gets more precise every session, from its own proven evidence (not guesses).

Backends (provider-agnostic, like the model layer):
  * **SQLite** (default) — a local `kg` table; works immediately, no new infra.
  * **Neo4j** (opt-in) — set MCPRT_GRAPH=neo4j + NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD; stores
    (Technique)-[:CONFIRMED_ON]->(Tool) and enables multi-hop graph reasoning as the corpus grows.

Only GROUND-TRUTH-confirmed observations are recorded — the knowledge is proof, never opinion.
"""
from __future__ import annotations

import os
import time
from pathlib import Path


class KnowledgeStore:
    name = "base"

    def record(self, technique: str, tool: str, *, outcome: str = "confirmed",
               cwe: str = "", target: str = "") -> None:
        raise NotImplementedError

    def recall(self, tools: list[str], *, limit: int = 6) -> list[dict]:
        """Return ranked past confirmations relevant to these target tools:
        [{technique, tool, count}], most-proven first."""
        raise NotImplementedError


class SqliteKnowledge(KnowledgeStore):
    name = "sqlite"

    def __init__(self, path: str | None = None):
        import sqlite3
        p = Path(path or os.getenv("MCPRT_KG_PATH") or (Path.home() / ".mcp-rt" / "knowledge.db"))
        p.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(p))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS kg(id INTEGER PRIMARY KEY, technique TEXT, tool TEXT, "
            "outcome TEXT, cwe TEXT, target TEXT, created_at REAL)")
        self.conn.commit()

    def record(self, technique, tool, *, outcome="confirmed", cwe="", target=""):
        self.conn.execute(
            "INSERT INTO kg(technique,tool,outcome,cwe,target,created_at) VALUES(?,?,?,?,?,?)",
            (technique, tool, outcome, cwe, target, time.time()))
        self.conn.commit()

    def recall(self, tools, *, limit=6):
        rows = self.conn.execute(
            "SELECT technique, tool, COUNT(*) c FROM kg WHERE outcome='confirmed' "
            "GROUP BY technique, tool ORDER BY c DESC LIMIT 200").fetchall()
        toks = {t.lower() for t in (tools or [])}
        def relevance(r):   # boost observations whose tool keyword overlaps the target's tools
            tool = (r["tool"] or "").lower()
            overlap = any(tool and (tool in t or t in tool) for t in toks)
            return (1 if overlap else 0, r["c"])
        rows = sorted(rows, key=relevance, reverse=True)[:limit]
        return [{"technique": r["technique"], "tool": r["tool"], "count": r["c"]} for r in rows]

    def close(self):
        self.conn.close()


class Neo4jKnowledge(KnowledgeStore):
    name = "neo4j"

    def __init__(self, uri=None, user=None, password=None):
        import neo4j
        self.driver = neo4j.GraphDatabase.driver(
            uri or os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=(user or os.getenv("NEO4J_USER", "neo4j"),
                  password or os.getenv("NEO4J_PASSWORD", "")))

    def record(self, technique, tool, *, outcome="confirmed", cwe="", target=""):
        with self.driver.session() as s:
            s.run("MERGE (t:Technique {name:$tech}) MERGE (o:Tool {name:$tool}) "
                  "MERGE (t)-[r:CONFIRMED_ON]->(o) SET r.count=coalesce(r.count,0)+1, r.cwe=$cwe",
                  tech=technique, tool=tool, cwe=cwe)

    def recall(self, tools, *, limit=6):
        with self.driver.session() as s:
            res = s.run("MATCH (t:Technique)-[r:CONFIRMED_ON]->(o:Tool) "
                        "RETURN t.name technique, o.name tool, r.count c ORDER BY c DESC LIMIT $lim",
                        lim=limit)
            return [{"technique": x["technique"], "tool": x["tool"], "count": x["c"]} for x in res]

    def close(self):
        self.driver.close()


def get_store() -> KnowledgeStore:
    """Neo4j when MCPRT_GRAPH=neo4j AND creds set; else the local SQLite knowledge store."""
    if os.getenv("MCPRT_GRAPH") == "neo4j" and os.getenv("NEO4J_URI"):
        try:
            return Neo4jKnowledge()
        except Exception:  # noqa: BLE001 — unreachable Neo4j -> fall back, never block the scan
            pass
    return SqliteKnowledge()


def recall_hints(tools: list[str], *, store: KnowledgeStore | None = None) -> str:
    """A short prompt-ready summary of what has historically worked on similar targets."""
    store = store or get_store()
    hits = store.recall(tools)
    if not hits:
        return ""
    lines = "; ".join(f"{h['technique']} (confirmed {h['count']}x" +
                      (f" on `{h['tool']}`)" if h['tool'] else ")") for h in hits)
    return ("Prior ground-truth confirmations on similar servers (prioritise these, they have "
            f"actually worked before): {lines}.")
