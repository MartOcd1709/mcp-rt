# Client Intake — what a client gives us, and how it maps to the engine

**Beta asset.** This is the single page a design-partner reads before an engagement. The principle: a client hands us their **existing MCP config** — we do not invent a new format. Whatever their agent already launches, we scan.

## The one rule that makes intake safe

- **Local / self-hosted servers** (stdio, launched by command): no authorization needed — the client runs them, we launch a copy against planted honeytokens. This is the Basic scan.
- **Remote / hosted servers** (an HTTP URL we don't control): we scan **only** with written authorization. The `remote` command refuses to run without `--authorized-by "<name, role, date>"`. No exceptions.

## What the client provides

Pick the row that matches how their MCP server runs. Column 3 is the exact command we run — nothing else is needed.

| They run MCP via… | They give us… | We run |
|---|---|---|
| A launch command (npx/uvx/python) | the command string + any required env (API keys) | `mcp-rt report --target-stdio "npx -y their-server"` |
| A standard `.mcp.json` / `mcp_settings.json` (Cursor, Claude Desktop, VS Code) | the file (or repo path) | `mcp-rt fleet --config path/.mcp.json` — scans **every** server in it |
| A CI repo with MCP configs committed | repo read access | `mcp-rt ci` — auto-finds configs, scans, emits SARIF, gates the build |
| A hosted server (HTTP) | the URL **+ written authorization** | `mcp-rt remote --url https://… --authorized-by "Jane Doe, CISO, 2026-10-07"` |
| A fleet listed in a CMDB / CI table | a CSV/JSON of servers (see below) | `mcp-rt fleet --config fleet.json` |

### Secrets / env

A real MCP server often needs an API key to start (DB creds, a GitHub token, etc.). The client's `.mcp.json` already carries these under `env` — we read and pass them through to the server-under-test **in-process only**; they are never written to a report or ledger. If they send a bare command instead of a config, they append the env the server needs:

```jsonc
// .mcp.json — this is ALL we need; it's the file they already have
{
  "mcpServers": {
    "their-db":  { "command": "uvx", "args": ["their-mcp-db"], "env": { "DB_URL": "…" } },
    "their-git": { "command": "npx", "args": ["-y", "their-git-mcp"] }
  }
}
```

### CMDB / CI-table fleet

For a client who tracks MCP servers in a CMDB or CI inventory, they export the **in-scope rows** into the `.mcp.json` shape above — one `mcpServers` entry per CI. The engine scans every server in the config it's given, so **the config they export is itself the scope list**: in-scope rows go in, out-of-scope rows stay out. Keep a column in their CMDB export for **name**, **launch command (or URL)**, **required env**, and **owner** so the exported config is reproducible from the asset table.

## Scope + authorization (the written part)

Before any engagement the client confirms, in writing:

1. **In-scope servers** — the exact list (names + commands/URLs). Anything not listed is out of scope.
2. **Authorization to test** — for remote targets, the named person/role/date that goes into `--authorized-by` and the report header.
3. **Environments** — test against a **staging** instance where possible; we plant canary tokens and send injection payloads, which is safe against a disposable server but should not hit production data without sign-off.

## What they get back

- **Basic scan**: full OWASP MCP Top-10 report (HTML + PDF) — 11 ground-truth detection classes, per-tool coverage matrix, attack-surface map, and the **MCP06 intent-flow enabling-conditions** flag (surface signal, not a finding).
- **Advanced / Agent Red-Team** (premium): confirms the MCP06 intent-flow exposure with a real agent in the loop — the class the Basic scan only flags as a condition.

Every verdict is ground-truth (planted honeytoken / sentinel / canary), never a heuristic. A clean report says clean; we do not pad.
