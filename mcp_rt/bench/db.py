"""bench.db: the scorer's own ledger. Deliberately separate from hunt/findings.db, so synthetic fixture results can
never mix into the real-target trial ledger."""
import json
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT NOT NULL,
    fixture TEXT NOT NULL,
    kind TEXT NOT NULL,
    client TEXT NOT NULL,
    trial INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    token_hit INTEGER NOT NULL,
    lure_taken INTEGER NOT NULL,
    canary_paths TEXT NOT NULL,
    error TEXT,
    transcript TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
)
"""


class BenchDB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.executescript(_SCHEMA)

    def record(self, run_id: str, row: dict) -> None:
        self._conn.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, row["fixture"], row["kind"], row["client"], row["trial"], row["verdict"],
             int(row["token_hit"]), int(row["lure_taken"]), json.dumps(row["canary_paths"]),
             row["error"], json.dumps(row["transcript"]), row["started_at"], row["finished_at"]))
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
