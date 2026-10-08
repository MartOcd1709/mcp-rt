# MCP-CAP hunt — target list (Leg 1)

**What we're hunting:** a tool that exercises a capability its schema never declared — a `read`/`query`/
`list` tool that secretly opens a network socket (phone-home / telemetry / license check), writes a file,
or spawns a process. Detector is live-proven (fires on the overreach fixture, clean on Anthropic's server).

**How each target is run** (on a strace host — NOT executing here yet):
```
python -m hunt.cli hunt-cap --target-stdio "<install_cmd>"
```
Always re-run the two controls alongside a batch so we know the detector is behaving:
- clean control: `npx -y @modelcontextprotocol/server-filesystem /tmp/fs_allowed` → must be CLEAN
- fire control:  `python -m hunt.probe_fixtures.overreach_server` → must fire 2

Triage rule: a hit is a **hypothesis/lead**, never a finding, until the honeytoken confirm step fires and
the source is read. By-design (a fetch tool fetching) is not a gap — MCP-CAP only cares about the *undeclared* axis.

---

## Tier 1 — Highest signal: cloud/vendor servers (telemetry / SSO / phone-home likely)
Vendor-published servers routinely add usage analytics, license pings, or SSO callbacks that a read-only
tool would not declare. Biggest payoff: an undeclared egress in a widely-embedded vendor server.
- `uvx alibabacloud-observability-cloud-sso-mcp@0.3.0`   ← SSO + observability = egress-prone
- `uvx alibabacloud-maxcompute-mcp-server@0.1.8`
- `uvx alibabacloud-dts-mcp-server@0.1.4`
- `uvx alibabacloud-dms-mcp-server@0.1.23`
- `uvx alibabacloud-ack-mcp-server@1.0.2`
- `uvx alibabacloud-agentloop-memory-mcp-server@0.2.0`   ← "memory" store, may sync out
- `uvx alibaba-cloud-application-management-mcp-server@1.0.4`
- `uvx akamai-cloud-mcp@0.1.0`
- `uvx agent-builder-mcp-aws-transform`
- `uvx agent-builder-agentic-mcp-aws-transform`
- `npx -y @nogoo9/mcp-server-cloud-fs`

## Tier 2 — DB connectors (a query/read tool that writes or egresses to an extra host)
A `*_query`/`read` tool should only touch its configured DB. Watch for: an undeclared second network
connection (metrics/license), or a write to disk (caching, logging credentials).
- `npx -y mcp-mongodb@0.1.2`
- `npx -y mcp-mysql-service@1.0.3`
- `npx -y @sajithrw/mcp-mysql@1.0.0`
- `npx -y @huzhihui_c/mcp-postgres`
- `npx -y @fauzitech/mcp-postgres`
- `npx -y @fabriciofs/mcp-sql-server@1.0.7`
- `npx -y mcp-postgres-rw stdio`
- `npx -y @achmadya-dev/mcp-sqlite-query`
- `npx -y @lubo3395/mcp-sqlite-server`
- `uvx acquis-postgres-mcp`
- `uvx adb-mysql-mcp-server`
- `npx -y @ahmetbarut/mcp-database-server@1.2.0`
- `npx -y @nam088/mcp-database-server`

## Tier 3 — git / ssh / terminal (undeclared NETWORK is the tell; exec often by-design)
These legitimately exec, so exec rarely counts. The interesting gap: a git/ssh tool that opens an
*undeclared* outbound connection, or a "read"-named one that writes/spawns.
- `npx -y yl-mcp-git-server`            (already a confirmed CWE-78 — re-check its CAP surface)
- `npx -y mcp-git-auditor`
- `uvx active-claude-github-mcp`
- `uvx airesearch-gitmem-mcp`
- `npx -y -p d33naz-mcp-git mcp-git`    (already confirmed CWE-22 — CAP cross-check)
- `npx -y @huzhihui_c/mcp-ssh`
- `npx -y @iflow-mcp/mcp-ssh-manager`
- `npx -y @fkom13/mcp-sftp-orchestrator`
- `npx -y @seepine/mcp-terminal`

## Tier 4 — fetch / scrape / upload (network by-design → hunt undeclared WRITE or EXEC)
Network won't flag (declared). Value here is a fetch/upload tool that *also* writes to disk outside a
temp dir, or spawns a process.
- `npx -y firecrawl-mcp`
- `uvx ai-first-scraper-mcp@1.0.2`
- `uvx agentfetch-mcp`
- `uvx aiohttp-mcp@0.7.0`
- `npx -y @objekt.sh/mcp-upload@0.1.5`
- `npx -y mcp-server-fetch` / `uvx mcp-server-fetch`

## Tier 5 — filesystem / pdf / file-tools (read-declared tools that write or egress)
Lots of "read file" / "read pdf" tools — a prime MCP-CAP shape (declares read, does more).
- `npx -y @dev.saqibaziz/mcp-pdf-reader@1.1.0`
- `npx -y @rturv/mcp-pdf-reader@1.0.0`
- `npx -y @johnv/mcp-file-analyzer`
- `npx -y @rog0x/mcp-file-tools`
- `npx -y @cynosure-mcp/file-access`
- `npx -y @exoticknight/mcp-file-merger@1.0.1`
- `npx -y @agent-infra/mcp-server-filesystem`

## Control anchors (run every batch — regression guard)
- CLEAN control: `npx -y @modelcontextprotocol/server-filesystem /tmp/fs_allowed`
- CLEAN control: `npx -y @modelcontextprotocol/server-everything`  (broad tool surface, should stay clean)
- FIRE control:  `python -m hunt.probe_fixtures.overreach_server`

## Not yet in the ledger — marquee servers worth adding (highest impact if they overreach)
Big-org-embedded servers; a telemetry/phone-home gap here is the headline finding. Add + hunt:
- **Atlassian / Jira MCP (Ved connecting tomorrow, 2026-10-08)** — HUNT PATH DEPENDS ON SHAPE:
  - If it's a **local stdio** Atlassian server (e.g. `sooperset/mcp-atlassian` launched with a Jira API
    token) → `hunt-cap` applies directly; a read/search-Jira tool that egresses anywhere other than the
    configured Atlassian host = an MCP-CAP lead. Use a disposable/test Jira token, synthetic data only.
  - If it's the **official hosted/remote** Atlassian MCP (OAuth, `mcp-remote` to a cloud endpoint) → NOT an
    MCP-CAP target (strace only sees a local process); route it through `mcp-rt remote --url … --authorized-by`
    (consent-gated OAuth-posture probe) instead. Confirm which shape before hunting.
- GitHub official MCP · Slack MCP · Sentry MCP · Notion MCP · Stripe MCP · AWS Labs MCP suite ·
  Playwright (`@playwright/mcp`, in ledger) · Puppeteer MCP · Context7 · Grafana MCP

---
### Suggested order
Tier 1 → Tier 5 → Tier 2 (the read-declared shapes in T1/T5 are the likeliest first finding), then T3/T4.
Record every run with `--record` (once wired) so leads land in the `hypotheses` table and the denominator grows.
