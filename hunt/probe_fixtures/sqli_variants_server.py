"""SQL-injection VARIANT server — the Tier-B generality battery for #58.

Novel tool/param names (ledger_find, row_by_id, boolean_lookup, error_lookup, count_rows, ledger_sql,
echo_reject; params needle, rowkey, probe_key, rowtag, sql_text) appear NOWHERE in hunt/probes.py — the
probe must discover them dynamically. Cases, one per class:
  * ledger_find   — string-context UNION-injectable (returns labels)          -> VULNERABLE (proof)
  * row_by_id     — NUMERIC-context UNION-injectable                          -> VULNERABLE (proof)
  * boolean_lookup— returns only a COUNT (no UNION-visible rows), true/false split -> SUSPECTED (inference)
  * error_lookup  — success is a fixed 'ok'; only SQL errors surface           -> SUSPECTED (inference)
  * count_rows    — PARAMETERIZED (bound values) — the anti-false-positive anchor -> CLEAN
  * ledger_sql    — a by-design SQL runner                                     -> by_design / CLEAN
  * echo_reject   — rejects and REFLECTS the input, evaluates no SQL           -> CLEAN (no reflection FP)

NOT a real target. Local, offline; used only by tests/test_sqli_variants.py.
"""
from __future__ import annotations

import sqlite3

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("sql-ledger")

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE ledger(id INTEGER PRIMARY KEY, label TEXT)")
_db.executemany("INSERT INTO ledger(label) VALUES (?)", [("alpha",), ("bravo",), ("charlie",), ("delta",)])
_db.commit()


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    def s(p):
        return {"type": "object", "properties": {p: {"type": "string"}}, "required": [p]}
    return [
        types.Tool(name="ledger_find", description="Search the ledger table for labels containing a needle.",
                   inputSchema=s("needle")),
        types.Tool(name="row_by_id", description="Fetch a label from the ledger table by row key.",
                   inputSchema=s("rowkey")),
        types.Tool(name="boolean_lookup",
                   description="Count ledger table rows whose label contains a probe key.",
                   inputSchema=s("probe_key")),
        types.Tool(name="error_lookup", description="Show whether a tag exists in the ledger table.",
                   inputSchema=s("rowtag")),
        types.Tool(name="count_rows",
                   description="Count ledger table rows whose label contains a tag, using a bound parameter.",
                   inputSchema=s("rowtag")),
        types.Tool(name="ledger_sql", description="Execute a SQL query against the ledger database and return the rows.",
                   inputSchema=s("sql_text")),
        types.Tool(name="echo_reject", description="Search ledger entries for a needle.",
                   inputSchema=s("needle")),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    def work() -> str:
        if name == "ledger_find":                # string-context UNION-injectable: rows are returned
            q = f"SELECT label FROM ledger WHERE label LIKE '%{arguments['needle']}%'"
            return "\n".join(str(r[0]) for r in _db.execute(q).fetchall()) or "(no rows)"
        if name == "row_by_id":                  # numeric-context UNION-injectable
            q = f"SELECT label FROM ledger WHERE id = {arguments['rowkey']}"
            return "\n".join(str(r[0]) for r in _db.execute(q).fetchall()) or "(no rows)"
        if name == "boolean_lookup":             # boolean-only: returns a COUNT, never UNION-visible row data
            q = f"SELECT COUNT(*) FROM ledger WHERE label LIKE '%{arguments['probe_key']}%'"
            return f"matches: {_db.execute(q).fetchone()[0]}"
        if name == "error_lookup":               # error-only: success is a fixed 'ok'; errors surface
            q = f"SELECT label FROM ledger WHERE label = '{arguments['rowtag']}'"
            _db.execute(q).fetchall()
            return "ok"
        if name == "count_rows":                 # PARAMETERIZED: bound values — the anti-FP anchor
            n = _db.execute("SELECT COUNT(*) FROM ledger WHERE label LIKE ?",
                            (f"%{arguments['rowtag']}%",)).fetchone()[0]
            return f"count: {n}"
        if name == "ledger_sql":                 # by-design SQL runner
            return "\n".join(str(r) for r in _db.execute(arguments["sql_text"]).fetchall()) or "(no rows)"
        if name == "echo_reject":                # rejects + REFLECTS the input; evaluates no SQL
            return f"invalid query: {arguments['needle']}"
        return "unknown tool"
    try:
        out = await anyio.to_thread.run_sync(work)
    except Exception as exc:  # noqa: BLE001 — the SQL error is the signal; surface it as text
        out = f"error: {exc}"
    return [types.TextContent(type="text", text=str(out)[:4096])]


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="sql-ledger", server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(), experimental_capabilities={})))


if __name__ == "__main__":
    anyio.run(_amain)
