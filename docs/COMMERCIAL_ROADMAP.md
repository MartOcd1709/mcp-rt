# Commercial Roadmap — Match Appsecco, Then Beat It (2026-10-06)

## ⭐ North Star (one-glance)
**Goal: a working, demo-able HOSTED ADMIN PLATFORM before London / Black Hat EU 2026 (~early Dec)** —
admin login, run the whole engine from a UI (scan · monitor · CI · fleet), browse the ledger + findings,
download reports, with everything logged/persisted in the backend; plus **CMDB/CI-driven fleet scanning**
(assess the customer's inventoried MCP servers, map results back to CIs). Built by wrapping the proven
engine (CLI→API). Local-first (no server/$0) → deploy to a VPS/cloud when funded or a design partner lands.

**Where we are (2026-10-06):** engine proven — 11 ground-truth classes · 150+ servers assessed · 0 false
positives · 2 CVE-class findings (1 filed to VulnCheck). Phase A (deliverable parity) ✅ · Phase B
(continuous/CI/fleet) ✅ · product site v1 up (needs design polish to client-grade). Discipline sacred:
ground-truth only, by-design≠vuln, never fabricate a finding OR a feature, disclose before publish.

**Path:** polish site → architecture session for the platform (Ved calls it) → build local-first admin
console (wrap the engine) → add CMDB/CI fleet ingestion → demo at Arsenal → hosted/multi-tenant AFTER London.

## Product model + deployment (Ved 2026-10-06 — confirmed; deployment = separate architecture-session topic)
- **Coverage = moat:** keep extending the ground-truth checks most vendors miss (we already exceed
  description-scanners), but add only CONFIRMABLE classes (discipline). "Most complete + every check proven."
- **Enriched corpus = continuously-growing ASSET, not a finish line.** CTO correction to "ready once DB
  complete": the DB is never complete (new servers daily) → we're already credible at 150+/0-FP; ship +
  validate NOW (beta), enrich FOREVER (daily loop). Don't gate launch on DB "completeness".
- **Client flow:** client gives minimal input — server config / endpoint / CMDB list + written
  authorization → we scan → report. Small input, big output.
- **DEPLOYMENT (separate deep discussion, part of architecture session): ON-PREM is a STRENGTH for us.**
  Engine is local-first (scans on-host, synthetic markers, nothing leaves) → on-prem appliance (runs inside
  the client's network; their servers/creds never leave) is NATURAL and is what security-sensitive clients
  demand (data-residency/compliance). Platform can ship on-prem appliance OR hosted SaaS OR both. Decide
  in the architecture session.

## Design-partner / beta feedback program (Ved idea 2026-10-06 — THE validation move, do in parallel)
Give the product to a few companies to test + collect feedback — validates demand (our #1 gap) and
produces case studies, using the **shipping scanner + report** (no platform needed yet). WHO: 3-5
AI-forward startups / dev-tool cos / MCP-server authors (not slow big enterprises). OFFER: free
ground-truth assessment of their MCP servers/fleet → the VAPT report + clean attestation, in exchange
for structured feedback + a testimonial/case study. ASK: is the report useful? would you pay? what's
missing? (feedback shapes the platform). DISCIPLINE: consent/scope only — never scan an unauthorized
server ([[feedback-scope-verification-before-testing]]). LANES: outreach = Ved (Arsenal network,
LinkedIn, MCP community, vendors we scanned); CTO preps the assets (offer one-pager · outreach note ·
feedback questions · a polished sample report). This is the hybrid-services play → near-term credibility
(+ maybe cash) while the platform builds toward London.

---

Open-source core is DONE (the funnel + credibility). Real development now = the **paid platform** on
top. Strategy: reach deliverable PARITY with Appsecco fast (so we're sellable), then ship the
EXTRAORDINARY layer a manual consultancy structurally cannot (continuous, inline, at scale) to capture
the market. Discipline unchanged: ground-truth only, never fabricate a finding OR a feature claim.

**Free core stays** (honest scanner = distribution/trust; Appsecco has NO free tier — our wedge).
Everything below is PAID.

## Phase A — PARITY: make the deliverable match theirs (fast, days each, highest near-term ROI)
Their engagement ships: full vuln report + PoC · exec summary · remediation w/ code · re-test in 30d ·
compliance-ready docs (SOC2/ISO27001/PCI). We have the vuln report + remediation + OWASP posture. Gaps:
- **A1. Executive summary** — leadership-facing section (risk posture, counts, top risks, plain English).
- **A2. Compliance crosswalk** — map our classes/OWASP-MCP to SOC2 / ISO 27001 / PCI DSS control
  families, so the report doubles as audit evidence (the "attestation" paid layer).
- **A3. Branded PDF deliverable** — one polished PDF a client/CISO receives (we emit MD/JSON today).
- **A4. Re-test / diff** — re-scan a target (we pin versions already) and show RESOLVED vs NEW.
→ Outcome: `mcp-rt report` becomes the exact artifact a buyer already pays Appsecco $3.5k–$15k for.

## Phase B — EXTRAORDINARY #1: continuous + shift-left (automation they can't staff)
- **B1. Continuous/scheduled monitoring + alerting** — we already have `daily`; formalize into a
  watched service: re-scan on every new version, alert on a NEW finding. "They test once; we test
  every version, every day." (A consultancy physically cannot re-test daily.)
- **B2. CI/CD GitHub Action** (Platform v2 Phase 1) — scan a repo's MCP config on every PR, SARIF to the
  Security tab, fail on critical. We live in the pipeline; a consultancy never can.
- **B3. Fleet + supply-chain view** — scan ALL a customer's MCP servers + their npm/PyPI supply chain
  continuously (we have the 131+ corpus + PyPI/npm discovery). They scope a handful.

## Phase C — EXTRAORDINARY #2: the category-redefining bets (weeks)
- **C1. Runtime proxy — PREVENTION, not just detection** (Platform v2 Phase 2). Inline, taint-track
  planted markers, BLOCK exfil in real time. Appsecco can only *report*; we *stop* it. Biggest moat.
- **C2. Exploit-chain correlation** ("the cash", Platform v2 Phase 2.5). Auto-compose confirmed
  low/meds into a PROVEN high-sev chain, demonstrated end-to-end. A human does this slowly; we automate+prove.
- **C3. AI-assisted remediation / auto-PR** — don't just say "use yaml.safe_load"; generate the patch
  / open the PR. Fix-not-just-find. (Ground-truth: re-scan proves the patch closed it.)

## Marketing site (v1 DONE 2026-10-06) + Hosted Admin Platform (Ved-directed, next after design)
- **Marketing/product site v1** published (artifact `claude.ai/artifact/GSLRJ8h9mJEkuE5ZfmAAwq`, copy at
  `~/Desktop/mcp-rt-site.html`): data-driven from the real ledger, strong-points framing (11 classes /
  150+ servers / 0 FP / 23-26 exfils — NO naked "2 confirmed"; findings as a quality proof point,
  disclosure-safe). Ved: "good but NOT client-deliverable yet" → needs design polish to client-grade
  before it fronts clients. Portable single HTML → host free on Netlify when ready.
- **HOSTED ADMIN PLATFORM (the real product, Ved-directed "once design is done"):** an admin-access web
  console that runs the ENTIRE engine from the UI — trigger scan / report / monitor / CI / fleet, browse
  the ledger + findings, download reports, manage monitored targets — with **all activity/results logged
  and persisted in the backend** (audit log + results; SQLite now → Postgres on a server). Architecture:
  backend API (FastAPI) wrapping the engine + auth(admin) + audit-log table; frontend admin dashboard.
  **HONEST: this is the hosted-product bet — it needs a SERVER (we have none/$0 budget).** Build path:
  a LOCAL-runnable admin console first (localhost, drives the engine, logs to the DB — Ved uses it as
  admin), deployable to a VPS/Oracle-free/cloud when funded or a design partner lands. Gated AFTER the
  marketing-site design reaches client-grade.

## CMDB / CI-driven fleet scanning (Ved idea 2026-10-06 — fleet + admin-platform capability)
Ingest the customer's asset inventory (CMDB / CI table, MCP servers as configuration items) → scan
every listed server → map results back to each CI (by name/IP, the KAVACH `KC_CSM_CI_ATTRIBUTES`
IP-match pattern), optionally write a security-posture attribute back to the CMDB record. Value =
"we assessed 100% of your INVENTORIED MCP fleet" → SOC2 asset-coverage attestation, continuous, beyond
a manual consultancy. Lean path: **CSV import of a CI table first** (cols: CI id · name · endpoint/cmd ·
owner) reusing `mcp-rt fleet`; ServiceNow/live-CMDB API connector later. HONEST sequencing: presupposes a
customer whose CMDB already inventories MCP servers (MCP is new → most don't yet) → architect fleet/
platform to ACCEPT a CMDB/CI source (ready for the right design partner), don't over-build the connector
before a customer needs it. Reuses Ved's KAVACH CI-linking know-how.

## Cross-cutting flywheel — the public MCP Security Benchmark / Leaderboard
A living, public scorecard of MCP-server security (graded, which are clean, which classes). Vendors want
their badge; it's a marketing flywheel + attestation moat **no consultancy has**. Built from stats.json
(disclosure-safe). This is how "whoever uses MCP is our client" becomes inbound.

## Sequencing (CTO recommendation)
**A (parity, sellable now) → B (continuous+CI, the automation wedge) → C (proxy+chaining, the moat).**
A funds the hybrid-services cash play immediately; B/C build the defensible product. Ship each
incrementally + verified; never a multi-month monolith. Benchmark/leaderboard runs alongside as marketing.

## Execution plan — milestones (rapid dev, test-gated). Each ships ONLY when its test is green.
Standard every milestone: `pytest` green · probe selftest green · `stats.json` derivation holds (no
hardcoded numbers) · disclosure-safe · WORKLOG entry. Prove worth with working+tested software, not claims.

| M | Phase | Deliverable | Definition of Done | Test | Size |
|---|---|---|---|---|---|
| **M1** | A1+A2 | Exec summary + compliance crosswalk in report | report.md has an Exec Summary block + an OWASP→SOC2/ISO27001/PCI crosswalk table | `test_report` asserts both render | S |
| M2 | A3 | Branded PDF deliverable (`report --pdf`) | one styled PDF emitted from the report dict | PDF file produced, non-empty | M |
| M3 | A4 | Re-test / diff (`mcp-rt diff <target>`) | compares scans across versions → RESOLVED / NEW / UNCHANGED | synthetic-ledger diff test | M |
| M4 | B1 | Continuous monitor + alert | re-scans tracked targets, flags NEW finding vs last scan | detects a planted new finding on re-scan | M |
| M5 | B2 | CI/CD GitHub Action | action.yml+entrypoint wrap `report --exit-code` → real SARIF | SARIF generated from vuln fixture | M |
| M6 | B3 | Fleet + supply-chain view | aggregate report over many targets + maintainer/downloads risk | aggregate-stats test | M |
| **M7** | C1 | Runtime proxy (PREVENTION) | inline stdio proxy blocks marker-tainted exfil, honest audit log | blocks exfil fixture, passes benign (zero-FP) | L |
| M8 | C2 | Exploit-chain correlation | compose confirmed findings → PROVEN chain, walked end-to-end | fixture: 2 lows compose→1 high w/ canary | L |
| M9 | C3 | AI-assisted remediation / auto-PR | generate patch; re-scan proves it closed the finding | patch closes the vuln fixture | M-L |
| Fw | flywheel | Public MCP Security Leaderboard | HTML leaderboard built from stats.json (disclosure-safe) | renders; names only published/clean | S-M |

**Cadence:** A (M1–M3) now → B (M4–M6) → C (M7–M9); Fw runs alongside as marketing. Ship incremental,
never a monolith; if a milestone's test isn't green it isn't done.

## What stays free (the funnel — do NOT close-source)
Single-server `mcp-rt report` + the standard detection classes + CLI + public scorecard. Honest,
full-coverage, labeled. Paid = everything in A/B/C above.
