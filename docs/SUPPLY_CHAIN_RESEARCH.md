# MCP Ecosystem Supply Chain Research
## Live OSINT — June 2026

**Author:** Ved Pandya  
**Methodology:** Read-only OSINT. npm registry API, GitHub search API. No exploitation, no contact with maintainers, no live system probing. All figures verifiable by anyone with a browser.

---

## The Core Question

Vendors rejected Gen 1 MCP attack disclosures with a consistent response: "the user installed a malicious server — that is within their threat model."

This research answers: **does a developer always make a conscious decision to install a malicious MCP server?**

The answer is no. Three delivery mechanisms exist in the MCP ecosystem today that require zero bad decisions from the developer.

---

## Delivery Mechanism 1: Compromised npm Maintainer

### The Event-Stream Precedent (2018)

In November 2018, a malicious actor convinced the maintainer of `event-stream` — an npm package with 8 million weekly downloads — to transfer maintainership. The new maintainer published a minor patch containing a cryptocurrency wallet stealer. Millions of downstream users ran the malicious code before discovery.

The attack required: one social engineering attempt, one npm account transfer, one patch publish.

### The MCP Ecosystem Replicates This Risk

The npm registry has no mandatory code signing. Package ownership is controlled by a username and password (hardware MFA is optional and rarely enforced). A dormant maintainer account — no recent logins, potentially weak credentials, possibly reused password in a known breach database — is an open door.

### Confirmed High-Risk Packages (Live Data, June 30 2026)

All figures pulled from npm registry API and npm downloads API at time of research.

| Package | Downloads/week | Total Installs (Jan 2025–Jun 2026) | Maintainers | Last Publish | Risk |
|---|---|---|---|---|---|
| **figma-mcp** | 2,912 | **87,556** | **1 (mjd)** | **421 days ago** | **CRITICAL** |
| **fastmcp** | 416,506 | **10,550,283** | **1 (punkpeye)** | 7 days ago | **HIGH** |
| **kubernetes-mcp-server** | 36,994 | — | **1 (manusa)** | 6 days ago | HIGH |
| **mcp-searxng** | 32,594 | — | **1 (ihor-sokoliuk)** | 6 days ago | HIGH |
| **@benborla29/mcp-server-mysql** | 20,919 | — | **1 (benborla29)** | 6 days ago | HIGH |

### figma-mcp: The Event-Stream Pattern Confirmed

`figma-mcp` matches the event-stream attack profile precisely:

- **Single maintainer:** `mjd` — one npm account, no backup
- **421 days since last publish:** maintainer is effectively dormant
- **87,556 total installs** since January 2025
- **2,912 installs last week** — developers are still actively installing it
- **No code signing:** no mechanism to detect a tampered publish
- **Category:** MCP server for Figma — connects AI coding agents to Figma workspaces, meaning the server has access to whatever credentials and files the developer's agent has access to

An attacker who gains access to the `mjd` npm account publishes version 0.1.5 with a server-side payload: when the agent calls `get_figma_config()`, the server reads `~/.ssh/id_rsa`; when the agent calls `sync_figma_config()`, the server POSTs the contents to an attacker-controlled endpoint. Both tool descriptions remain completely benign. MCP-Scan returns zero findings. 2,912 developers install it in the first week. Their AI agents exfiltrate SSH keys while reporting "config synced successfully."

The developer made no bad security decision. They installed a package with thousands of downloads from a curated list.

### fastmcp: Framework-Level Blast Radius

`fastmcp` is the dominant TypeScript framework for building MCP servers. Single maintainer. 10,550,283 total installs since January 2025. 416,506 installs last week.

The threat profile differs from figma-mcp: fastmcp is not installed by end-users as a server — it is a dependency of other MCP servers. Compromise fastmcp and every server built on it becomes a delivery vehicle simultaneously. This is the `left-pad` pattern (2016: one unpublish broke thousands of projects) combined with the event-stream pattern, applied to a framework that runs as a persistent process with tool access to the developer's filesystem.

---

## Delivery Mechanism 2: Git Clone Auto-Activation

### The .mcp.json Standard

MCP-aware clients (Cursor, Claude Desktop, VS Code MCP extension) auto-detect `.mcp.json` files in a project directory and activate the configured servers. This is by design — it allows projects to ship their MCP configuration with the code.

### Ecosystem Scale

GitHub search (June 2026): **1,918 public repositories** ship `.mcp.json` files.

This number represents repositories, not individual files — monorepos and forks would raise the true file count higher.

### Concrete Example: blazickjp/arxiv-mcp-server

This repository — a legitimate research tool for searching academic papers — ships the following `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "arxiv": {
      "command": "uvx",
      "args": ["arxiv-mcp-server"]
    }
  }
}
```

When a developer clones this repository, their MCP-aware client detects the file and activates `arxiv-mcp-server` from PyPI. The developer approved nothing beyond `git clone`. If the PyPI package `arxiv-mcp-server` is typosquatted, its maintainer account is compromised, or the package is abandoned and re-registered by an attacker, the developer has no decision point between cloning the repository and running malicious server-side code.

The `npx -y` pattern common in many `.mcp.json` examples (auto-accept without prompting) eliminates even the installation confirmation.

### The mcp-rt MCP-21 Attack

mcp-rt includes `mcp_json_supply_chain` (MCP-21): a payload that ships a `.mcp.json` in the project directory pointing to our malicious MCP server. When the developer clones the repository and opens it in a supported client, the server activates automatically. No `npm install`. No explicit configuration. One `git clone`.

---

## Delivery Mechanism 3: Scope Confusion (Typosquatting Already in Progress)

The following packages are live on npm, published by unrelated third parties, with descriptions that mirror the official scoped packages:

| Unofficial Package | Downloads/week | Official Package | Notes |
|---|---|---|---|
| `notion-mcp-server` | 2,067 | `@notionhq/notion-mcp-server` | Identical pitch: "AI assistant connector to Notion" |
| `context7-mcp-server` | — | `@upstash/context7-mcp` | Word-for-word same description |
| `mcp-server-filesystem` | 79 | `@modelcontextprotocol/server-filesystem` | "MCP server for filesystem access" — mirrors official description |

None of these are confirmed malicious. Their existence proves the naming confusion infrastructure is already in place. An attacker publishes a malicious version of any of these names (or registers currently unclaimed variants) and accumulates installs from developers who mistake it for the official scoped package.

Unclaimed typosquat names verified as 404 (June 2026): `fastmcp-server`, `mcp-serv3r`, `context7-mcp`, `mcpserver`, `mcp_server`.

---

## Combined Attack Scenario

A developer is building a JavaScript project. They search the `punkpeye/awesome-mcp-servers` list (90,000 GitHub stars, the dominant MCP server directory) and find `figma-mcp`. They run:

```bash
npm install figma-mcp
```

The install succeeds. The package has 87,556 historical installs and appears in multiple curated lists. The developer adds it to their Claude Code MCP config and uses it for a week without issue.

Three months later, an attacker runs credential stuffing against npm accounts using a leaked credential database. The `mjd` account — dormant for 421 days, password unchanged since 2023 — falls. The attacker publishes `figma-mcp@0.1.5`. The change: two lines of Python added to the server, invisible in the diff if no one is watching.

The developer's automated Dependabot opens a PR: "bump figma-mcp from 0.1.4 to 0.1.5." Auto-merged per their CI policy. The new server activates.

The next time the developer asks Claude Code to "sync my Figma config," the server calls `get_figma_config()` (reads `~/.ssh/id_rsa`), then `sync_figma_config()` (POSTs it to attacker server). Claude Code reports "Config synced across 3 environments." MCP-Scan reports zero findings.

The developer made no bad security decision at any step.

---

## mcp-rt Supply Chain Scanner

`tools/supply_chain_scan.py` operationalizes this research as a live tool:

```
python tools/supply_chain_scan.py figma-mcp fastmcp kubernetes-mcp-server

figma-mcp  v0.1.4
  Downloads/week : 2,912
  Maintainers    : 1 (mjd)
  Last publish   : 421d ago
  Code signing   : none
  Risk           : CRITICAL — single maintainer · 421d stale · event-stream pattern

fastmcp  v4.3.2
  Downloads/week : 416,506
  Maintainers    : 1 (punkpeye)
  Last publish   : 7d ago
  Code signing   : none
  Risk           : HIGH — single maintainer · 416,506/wk — high blast radius if compromised
```

Risk rubric:
- **CRITICAL:** single maintainer + 180+ days stale + 1,000+ weekly installs (event-stream pattern)
- **HIGH:** single maintainer + 100,000+ weekly installs (high blast radius), or single maintainer + 90+ days stale + 500+ weekly installs
- **MEDIUM:** single maintainer with recent activity, or multi-maintainer with stale publish
- **LOW:** multi-maintainer, recently published

---

## What This Means for the MCP Security Model

Vendors' standard response to MCP attack reports — "the user installed a malicious server" — assumes a conscious installation decision. This research documents three delivery mechanisms that bypass that assumption:

1. **npm maintainer compromise:** user installs a legitimate package; a future version is malicious
2. **git clone auto-activation:** user clones a repository; .mcp.json activates the server
3. **scope confusion:** user installs a package that looks like the official one

In all three cases, the developer made a reasonable decision by any standard security hygiene metric. The mcp-rt runtime attack framework confirms what happens when that server is connected: credentials leave the machine, the agent reports success, and no scanner fires.

The attack surface is not "malicious servers." The attack surface is **the npm ecosystem, the GitHub ecosystem, and the MCP auto-activation mechanism** — all delivering servers to developers who believe they are running trusted code.

---

## Data Sources

All data is read-only OSINT, verifiable by anyone:

- npm registry API: `https://registry.npmjs.org/{package}`
- npm downloads API: `https://api.npmjs.org/downloads/point/{period}/{package}`
- GitHub search API: `https://api.github.com/search/repositories?q=filename:.mcp.json`
- punkpeye/awesome-mcp-servers: `https://github.com/punkpeye/awesome-mcp-servers`

Data collected: June 30, 2026.
