# Prevalence of Exploitable Architecture Patterns Across Popular MCP Servers

Research note quantifying how many popular MCP servers implement the specific
architectural patterns that mcp-rt's confirmed attacks weaponize.

**Date:** 2026-07-03
**Method:** Read-only static analysis of public READMEs, package descriptions, and source. No live MCP server was connected, probed, or exploited. Every metric is traceable to a cited public source. This memo extends, and does not duplicate, `docs/SUPPLY_CHAIN_RESEARCH.md` (which quantifies delivery risk); here the question is architectural exposure, that is, how many popular servers implement the specific patterns mcp-rt's confirmed attacks weaponize.

---

## 1. Purpose

The Arsenal proposal (`docs/ARSENAL_PROPOSAL_INDIA.md`, "Architecture-Pattern Basis") grounds each confirmed attack class in one of the five MCP server patterns catalogued by Rodrigues and Vas (ICSME 2026, arXiv:2606.30317): Resource Gateway, Tool Orchestrator, Stateful Session Server, Proxy Aggregator, and Domain-Specific Adapter. That grounding is qualitative. This memo replaces the qualitative claim with counted prevalence across a defensible sample of the most-used real MCP servers, so the impact section can state what fraction of the deployed ecosystem implements each exploitable pattern.

Attack-to-pattern mapping under study (from the proposal):

| Confirmed attack class | Weaponized pattern |
|---|---|
| `server_side_workflow` | Tool Orchestrator |
| `cross_session_temporal` | Stateful Session Server |
| `api_error_injection` | Domain-Specific Adapter |
| `mcp_resource_injection` family | Resource Gateway |
| `cross_server_poisoning` (future work) | Proxy Aggregator |

---

## 2. Selection rule

The sample is the union of two publicly enumerable, popularity-ranked sets, chosen before classification to avoid cherry-picking:

- **Set A, official reference and archived servers:** every server listed in the `modelcontextprotocol/servers` repository README (7 active reference servers plus 13 archived first-party integrations). Source: `https://github.com/modelcontextprotocol/servers`, README retrieved 2026-07-03. These share one monorepo whose star count is 88,013 (GitHub API, `repos/modelcontextprotocol/servers`, retrieved 2026-07-03).
- **Set B, top third-party servers by install volume:** the most-downloaded independent MCP server packages from the June 2026 npm audit in `docs/SUPPLY_CHAIN_RESEARCH.md`, excluding `fastmcp` (a framework/SDK, not a server) and excluding duplicates already in Set A.

The union yields **35 distinct servers**. Frameworks and SDKs (`@modelcontextprotocol/sdk`, `fastmcp`) are excluded by definition because they are not servers. Aggregator/gateway tooling (for example `mcp-proxy`, `metamcp`) does not appear in either popularity-ranked set and is therefore absent from the sample; this absence is itself a finding, discussed in Section 5.

Install metrics are weekly downloads unless noted. Figures pulled this session are labelled "npm 2026-07-03" or "PyPI 2026-07-03"; figures reused from the June 30 2026 audit are labelled "SC-audit" and cite `docs/SUPPLY_CHAIN_RESEARCH.md`. Where a per-package download count could not be verified, the cell reads "unverified" and the monorepo star count stands as the availability metric.

---

## 3. Classification criteria

Each server is classified against the five patterns from its documented behaviour. A server may implement more than one. Criteria, held constant across the sample:

- **Resource Gateway (RG):** returns externally-sourced or stored content (files, documents, database rows, web pages, knowledge-base entries) into the model's context. This is the surface `mcp_resource_injection` exploits: unsanitized resource content is processed as instruction.
- **Tool Orchestrator (TO):** exposes tools that run multi-step server-side workflows or chained operations, the surface `server_side_workflow` exploits.
- **Stateful Session Server (SS):** persists state across calls or sessions (knowledge graph, database, cache), the surface `cross_session_temporal` exploits.
- **Proxy Aggregator (PA):** a single server fronts multiple independent upstream MCP servers and attributes their tools or resources to itself, the surface `cross_server_poisoning` targets. Applied strictly: a server that wraps many APIs of one vendor (for example Azure, Kubernetes) is a Domain-Specific Adapter, not a Proxy Aggregator, because provenance is not laundered across independent servers.
- **Domain-Specific Adapter (DSA):** wraps one specific third-party API or domain with a bespoke response and error surface, the surface `api_error_injection` exploits via crafted error text carried into context.

Independent risk capabilities, recorded separately from pattern:

- **File-read:** reads arbitrary local filesystem paths.
- **Egress:** makes outbound network calls.
- **Persistent-state:** retains cross-session or on-disk state.

---

## 4. Per-server classification

| # | Server | Install / star metric (source) | Patterns | File-read | Egress | Persistent-state |
|---|---|---|---|---|---|---|
| 1 | Filesystem (ref) | 390,693/wk npm (SC-audit) | RG | Yes | No | No |
| 2 | Fetch (ref) | unverified; monorepo 88,013★ | RG | No | Yes | No |
| 3 | Git (ref) | unverified; monorepo 88,013★ | RG, TO | Yes | No | No |
| 4 | Memory (ref) | 75,138/wk npm 2026-07-03 | SS, RG | No | No | Yes |
| 5 | Sequential Thinking (ref) | 91,712/wk npm 2026-07-03 | TO, SS | No | No | Yes |
| 6 | Time (ref) | 78,647/wk PyPI 2026-07-03 | DSA | No | No | No |
| 7 | Everything (ref) | 57,750/wk npm (SC-audit) | RG | No | No | No |
| 8 | GitHub (archived) | 139,500/wk npm 2026-07-03 | DSA, TO | No | Yes | No |
| 9 | GitLab (archived) | 8,444/wk npm 2026-07-03 | DSA, TO | No | Yes | No |
| 10 | Google Drive (archived) | unverified; monorepo 88,013★ | RG, DSA | No | Yes | No |
| 11 | Google Maps (archived) | 9,295/wk npm 2026-07-03 | DSA | No | Yes | No |
| 12 | PostgreSQL (archived) | 75,133/wk npm 2026-07-03 | RG, SS | No | Yes | Yes |
| 13 | SQLite (archived) | unverified; monorepo 88,013★ | RG, SS, TO | Yes | No | Yes |
| 14 | Redis (archived) | 2,249/wk npm 2026-07-03 | SS | No | Yes | Yes |
| 15 | Puppeteer (archived) | 29,680/wk npm 2026-07-03 | TO, RG | No | Yes | No |
| 16 | Brave Search (archived) | 20,569/wk npm 2026-07-03 | DSA, RG | No | Yes | No |
| 17 | Slack (archived) | 82,449/wk npm 2026-07-03 | DSA | No | Yes | No |
| 18 | Sentry (archived) | 69,897/wk npm (SC-audit) | DSA | No | Yes | No |
| 19 | AWS KB Retrieval (archived) | unverified; monorepo 88,013★ | RG, DSA | No | Yes | No |
| 20 | EverArt (archived) | unverified; monorepo 88,013★ | DSA | No | Yes | No |
| 21 | Notion (`@notionhq/notion-mcp-server`) | 167,192/wk npm (SC-audit) | DSA, RG | No | Yes | No |
| 22 | Azure (`@azure/mcp`) | 106,675/wk npm (SC-audit) | DSA | No | Yes | No |
| 23 | Supabase (`@supabase/mcp-server-supabase`) | 62,008/wk npm (SC-audit) | DSA, RG, SS | No | Yes | Yes |
| 24 | Kubernetes (`kubernetes-mcp-server`) | 36,994/wk npm (SC-audit) | TO, DSA | No | Yes | No |
| 25 | SearXNG (`mcp-searxng`) | 32,594/wk npm (SC-audit) | DSA, RG | No | Yes | No |
| 26 | MySQL (`@benborla29/mcp-server-mysql`) | 20,919/wk npm (SC-audit) | RG, SS | No | Yes | Yes |
| 27 | Datadog (`@winor30/mcp-server-datadog`) | 20,053/wk npm (SC-audit) | DSA | No | Yes | No |
| 28 | HubSpot (`@hubspot/mcp-server`) | 12,222/wk npm (SC-audit) | DSA | No | Yes | No |
| 29 | Context7 (`@upstash/context7-mcp`) | 1,044,045/wk npm (SC-audit) | RG, DSA | No | Yes | No |
| 30 | Chrome DevTools (`chrome-devtools-mcp`) | 3,090,449/wk npm (SC-audit) | TO, RG | No | Yes | No |
| 31 | Figma (`figma-mcp`) | 2,912/wk npm (SC-audit) | DSA, RG | No | Yes | No |
| 32 | Slite (`slite-mcp-server`) | 1,706/wk npm (SC-audit) | DSA, RG | No | Yes | No |
| 33 | Playwright (`@playwright/mcp`) | 5,770,364/wk npm 2026-07-03 | TO, RG | No | Yes | No |
| 34 | ESLint (`@eslint/mcp`) | 25,173/wk npm (SC-audit) | DSA | Yes | No | No |
| 35 | Penpot (`@penpot/mcp`) | 22,981/wk npm (SC-audit) | DSA, RG | No | Yes | No |

Notes on conservative calls: Memory and SQLite persist to a local store but are not counted under File-read because they read their own managed state, not arbitrary user paths; only servers that read caller-specified filesystem paths (Filesystem, Git, SQLite database path, ESLint source tree) are marked File-read. Azure and Kubernetes wrap many services of a single vendor and are classified DSA rather than Proxy Aggregator per the strict criterion in Section 3.

---

## 5. Aggregate results (n = 35)

Pattern prevalence (a server may implement more than one):

| Pattern | Weaponizing attack | Count | Share of sample |
|---|---|---|---|
| Resource Gateway | `mcp_resource_injection` family | 21 | 60.0% |
| Domain-Specific Adapter | `api_error_injection` | 22 | 62.9% |
| Tool Orchestrator | `server_side_workflow` | 9 | 25.7% |
| Stateful Session Server | `cross_session_temporal` | 7 | 20.0% |
| Proxy Aggregator | `cross_server_poisoning` (future) | 0 | 0.0% |

Coverage of the confirmed corpus: **35 of 35 servers (100%) implement at least one of the four patterns that mcp-rt's confirmed attacks weaponize** (RG, DSA, TO, or SS). Every popular server in the sample is in scope for at least one confirmed attack class.

Risk-capability prevalence:

| Capability | Count | Share |
|---|---|---|
| Makes outbound network calls (egress) | 27 | 77.1% |
| Holds persistent / cross-session state | 7 | 20.0% |
| Reads arbitrary local files | 4 | 11.4% |

Combined surfaces relevant to injection-plus-exfiltration:

- **Resource Gateway that also makes outbound calls (ingests untrusted external content and can call out from the same process): 16 of 35, 45.7%.** This is the single-process injection-and-exfiltration surface: a server that both pulls attacker-influenceable content into context and holds an egress channel. Servers: Fetch, Google Drive, PostgreSQL, Puppeteer, Brave Search, AWS KB, Notion, Supabase, SearXNG, MySQL, Context7, Chrome DevTools, Figma, Slite, Playwright, Penpot.
- **Reads local files and makes outbound calls in the same server: 0 of 35, 0%.** No popular server both reads arbitrary local files and egresses. The local-file-exfiltration scenario in `docs/SUPPLY_CHAIN_RESEARCH.md` (a server reading `~/.ssh/id_rsa` and POSTing it) is therefore realized not within a single popular server but across servers, when a file-reading server (Filesystem, Git) shares a client session with an egress-capable server. This empirically motivates the cross-server threat model rather than weakening it.

Proxy Aggregator is absent from the popularity-ranked sample (0%). The pattern exists in the ecosystem as dedicated gateway tooling that did not rank into either popularity set. This is consistent with the proposal treating `cross_server_poisoning` as future work rather than a confirmed result: the pattern it targets is real but not yet among the highest-install single servers.

---

## 6. Caveats

- Pattern classification is a judgement from public documentation and, where consulted, source. It is auditable per row in Section 4 but not machine-verified; a reviewer may reasonably reclassify a borderline server, which would move an aggregate by roughly 2.9 percentage points per server.
- Install counts are weekly download or star snapshots, not unique deployments; downloads over-count CI and mirror traffic. They index popularity, not installed base.
- Five per-package download counts (Fetch, Git, Google Drive, SQLite, AWS KB, EverArt) could not be verified this session; those rows rely on the shared 88,013-star monorepo as the availability metric and are labelled unverified rather than estimated.
- The sample is popularity-weighted by construction and is not a random draw from all MCP servers; it characterizes the servers developers are most likely to run, which is the population the impact claim concerns.

---

## 7. Recommended text for the Arsenal impact section

> Across a sample of 35 of the most-installed real MCP servers, drawn from the official `modelcontextprotocol/servers` reference set and the highest-download third-party servers on npm, every server (35 of 35, 100%) implements at least one of the four architecture patterns that mcp-rt's confirmed attacks weaponize. Sixty percent implement the Resource Gateway pattern targeted by the `mcp_resource_injection` family and 62.9% implement the Domain-Specific Adapter pattern targeted by `api_error_injection`, while 25.7% and 20.0% respectively expose the Tool Orchestrator and Stateful Session surfaces. Nearly half the sample (45.7%) both ingest externally-sourced content and hold an outbound network channel in the same process, the minimum condition for single-server injection-and-exfiltration; the remainder of the exfiltration exposure is cross-server, which is precisely the topology mcp-rt models. The exploitable surface is therefore not a property of rare or malicious servers but of the dominant, sanctioned architecture patterns the popular ecosystem is built on.

---

## 8. Sources

- Official reference server list: `https://github.com/modelcontextprotocol/servers` (README, retrieved 2026-07-03).
- Monorepo star count: GitHub API `repos/modelcontextprotocol/servers`, `stargazers_count = 88,013` (retrieved 2026-07-03).
- npm weekly downloads: npm downloads API `https://api.npmjs.org/downloads/point/last-week/{package}` (retrieved 2026-07-03) for Memory, Sequential Thinking, Puppeteer, Brave Search, Slack, GitHub, GitLab, Google Maps, PostgreSQL, Redis, and `@playwright/mcp`.
- PyPI weekly downloads: pypistats API `https://pypistats.org/api/packages/mcp-server-time/recent` (retrieved 2026-07-03). Fetch and Git PyPI counts rate-limited this session and left unverified.
- Third-party install figures labelled SC-audit: `docs/SUPPLY_CHAIN_RESEARCH.md`, "Full Top-20 MCP Package Audit," npm registry and downloads APIs, collected 2026-06-30.
- Pattern taxonomy: Rodrigues and Vas, "MCP Server Architecture Patterns for LLM-Integrated Applications," ICSME 2026, arXiv:2606.30317, as cited in `docs/ARSENAL_PROPOSAL_INDIA.md`.
