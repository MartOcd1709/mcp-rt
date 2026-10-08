# MCP-RT Platform v2.0 — Enriched Working Plan

> CTO working document (2026-10-05). This is the corrected, buildable version of the pasted
> "Platform v2.0" spec. It maps the vision onto what we actually have, fixes the defects in the
> draft code, sequences the work realistically, and keeps our core discipline: **ground truth,
> zero false positives, by-design ≠ vuln, consent-gated, local-only.**

## 0. What the pasted spec got right vs wrong (read first)

**Right (keep the direction):** the strategic arc is correct — evolve from a *scanner* into a
*platform*: (1) pre-deployment scanning → (2) real-time runtime protection → (3) shift-left CI/CD →
(4) multi-agent monitoring. That arc is what turns a tool into a product.

**Wrong (do NOT inherit):**
1. **Targets the wrong codebase.** The spec's file tree (`mcp_rt/honeytoken.py`, `harness.py`,
   `payloads/`, adapters) is the **Black Hat Arsenal research corpus**. Our **product engine is
   `hunt/`** (10 ground-truth probes, sweep/daily, report, benchmark, scorecard, remote,
   findings_db). New features must integrate with both, correctly — see §1.
2. **Broken taint model.** The draft hashes whole file content (`sha256(content)`) and then checks
   `if tainted_hash in content` — a hash never appears inside content, and any reformat/truncate/
   concat defeats full-content hashing. This would both false-positive and false-negative. **Fix:
   taint = our honeytoken/canary MARKER substring match** (we already plant high-entropy markers;
   detecting the marker in an outbound arg is ground truth, zero-FP). See §3 Phase 2.
3. **Broken async proxy.** The draft reads sync `sys.stdin` with `await reader.readline()` and calls
   `asyncio.run()` twice (the server subprocess from loop #1 is dead in loop #2). Also no MCP
   framing handling. **Fix: single event loop, real async stdio wiring, proper JSON-RPC framing.**
4. **Policy false positives.** Network detection by tool-name substring (`http`/`get`/`post`) flags
   `get_weather` as egress. **Fix: by-design-aware policy** (declared egress vs tainted-data-to-
   egress), same nuance the probes already enforce.
5. **Placeholder CI.** The GitHub Action emits empty SARIF and calls a non-existent
   `mcp_rt.tools.supply_chain_scan`. **Fix: wrap the real `mcp-rt report --exit-code` + real SARIF.**
6. **Unrealistic 7-day timeline.** A correct inline proxy is ~2–3 weeks alone. Re-sequenced in §3.
7. **Sells roadmap as shipping.** The client brief claims we *provide* real-time protection today.
   We don't yet. The deck MUST separate Shipping from Roadmap (§4) — same honesty rule as findings.

## 1. What we actually have (the real baseline)

**`hunt/` — the product engine (shipping):**
- 10 ground-truth detection classes + `mcp-rt` CLI (`scan/probe/token/report/benchmark/sweep/daily/
  remote/scorecard`). Every verdict proven by planted honeytoken/sentinel/canary — not heuristics.
- `report.py` → unified VAPT + OWASP MCP Top 10 report (MD/JSON), `--exit-code` CI gate already exists.
- `sweep.py`/`daily.py` → discovery (long-tail + **popular/high-usage lanes**) + enrich + dated run
  logs; `findings_db.py` ledger (SQLite, Postgres-ready). `scorecard.py` → public read-only proof.
- `remote.py` → consent-gated hosted scan (DNS-rebinding + missing-auth enforcement checks).

**`mcp_rt/` — the Black Hat Arsenal research corpus:**
- `honeytoken.py` (plant/fired/cleanup — **reuse for proxy taint markers**), `scan/runner.py`,
  `detect/`, `capture/proxy.py` (`LoopbackProxyBackend` — egress capture; relevant prior art for the
  runtime proxy), payloads + agent adapters. 23/26 confirmed agent exfils live here.

**Implication:** we already own the scanner (hunt) and honeytoken+exfil+egress-capture (mcp_rt). v2.0
adds: a runtime **inline** proxy, a **CI action**, and **cascade** detection — built on these, not from scratch.

## 2. The product thesis (how we sell it, honestly)

Two buyers, two value props — neither requires fabricating a finding:
- **Fleet exposure (fear, real):** an enterprise runs dozens of MCP servers, mostly community/long-tail
  where we *do* find bugs. "Which of your 40 servers leaks creds / has shell injection?" → the scanner.
- **Assurance / attestation (the bigger market):** ground-truth CLEAN across 10 classes + OWASP MCP
  Top 10 = evidence a vendor shows *their* customers. A clean top-server verdict is a product, not a failure.
- **Runtime protection (the leap):** the proxy blocks exfil in real time — the shift from "you were
  vulnerable" to "we stopped it." This is the enterprise wedge, and it's Phase 2.

## 3. Phased build plan (realistic, with acceptance criteria)

Discipline gates apply to EVERY phase: ground truth only · zero false positives · by-design ≠ vuln ·
local/consent-gated · a runnable test per non-trivial unit · responsible disclosure before publish.

### Phase 0 — Shipping engine (DONE / continuous)
Scanner + benchmark + daily enrich (3 lanes) + scorecard. **Status: live.** Keep enriching the ledger.

### Phase 1 — CI/CD GitHub Action  ·  ~1 week  ·  HIGHEST ROI, LOWEST RISK (do first)
Wrap the **existing** `mcp-rt report --exit-code` so a repo's `.mcp.json`/`mcp_settings.json` servers
are scanned on every PR, results posted as **real SARIF** to the GitHub Security tab.
- `.github/action/` (action.yml, Dockerfile with Node for npx, entrypoint).
- Real work: parse MCP config → for each stdio server run `mcp-rt report --target-stdio` → map findings
  to SARIF rules (CWE/OWASP from `CLASS_META`) → `--fail-on critical|high|any|none`.
- **Acceptance:** on a repo wired to the vuln fixture → non-empty SARIF, correct severities, CI fails
  per `--fail-on`; on a clean server → passes. No placeholder SARIF.
- Why first: reuses shipping code, drives adoption/visibility (the real bottleneck), days not weeks.

### Phase 2 — Runtime stdio proxy  ·  ~2–3 weeks  ·  THE DIFFERENTIATOR
Transparent inline proxy on the agent↔server stdio channel: taint-track planted markers, enforce
policy, block exfil, forensic audit log. `mcp_rt/proxy/` + `mcp-rt-proxy` entry point.
- **Taint = honeytoken markers, not content hashes.** Reuse `mcp_rt/honeytoken.py`: when a tool
  response carries a planted marker, taint that marker string; block an outbound tool call whose args
  contain a tainted marker AND reach egress. Ground truth, zero-FP. (Optional later: fuzzy/secret-
  pattern taint as *audit-only*, never *block*, to avoid FPs.)
- **Correct async core:** single event loop; wrap stdio via `asyncio` StreamReader/Writer (or reuse
  the MCP SDK transport); handle MCP JSON-RPC framing (newline-delimited AND Content-Length); one
  `start()` that launches the subprocess and pipes both directions in the same loop.
- **By-design-aware policy:** block = tainted-data → actual egress; a tool merely *named* `get_*` is
  not egress. Policies in YAML, same precision gates as the probes. Default: block exfil, audit tainted,
  allow rest.
- **Audit log:** JSONL, value-redaction, summary report.
- **Acceptance:** against our `server/malicious_mcp_server.py` exfil payloads → proxy BLOCKS the
  marker-bearing egress call and logs it; against a benign server doing legitimate HTTP → NOT blocked
  (zero FP); ground-truth test fixtures for both, in `tests/proxy/`.
- **Honest risk:** correct inline proxying is the hard part (framing, partial reads, backpressure,
  server crashes). Budget 2–3 weeks; do NOT ship a proxy that drops/corrupts traffic.

### Phase 2.5 — Exploit-chain correlation  ·  HIGH-VALUE ("the cash")  ·  ~1–2 weeks
Correlate individually-confirmed findings into a PROVEN high-severity attack chain. One critical
chain is worth far more (credibility + bounty) than three separate low/medium findings.
- **Input:** the ground-truth findings already in `findings_db` (per tool/server/class).
- **Correlation:** an LLM-assisted step proposes candidate chains across findings (e.g. info-leak →
  path-traversal read → write-escape → RCE; SSRF → 169.254.169.254 cloud-metadata → cred theft;
  missing_auth → tool_poisoning → silent exfil). The LLM only *proposes*; it never decides severity.
- **Ground-truth gate (non-negotiable):** a chain is a finding ONLY if the engine WALKS it end-to-end
  and a planted canary comes out the far end. A chain we cannot demonstrate is a hypothesis, logged as
  such, never reported as a finding. (This is the same zero-FP rule as the probes — speculated chains
  would reintroduce false positives and kill the moat.)
- **Output:** a chained finding with upgraded CVSS, the step graph, and the end-to-end PoC/transcript.
- **Acceptance:** on a fixture server with two individually-low bugs that compose to RCE → engine
  emits ONE chained HIGH/CRITICAL finding with a demonstrated canary; on bugs that look chainable but
  don't actually compose → logged as an unproven hypothesis, NOT a finding.
- **Why it matters:** this is the differentiator buyers fear and bounties pay for — "your three
  mediums are one critical." Build after Phase 2 (the proxy gives a runtime channel to demonstrate
  some chains), but it can start earlier as a pure correlation-over-ledger layer.

### Phase 3 — Multi-agent cascade detection  ·  ~1 week  ·  research-forward, lower priority
Detect when one planted honeytoken surfaces across multiple agents (compromise propagation).
`mcp_rt/cascade/` — record (agent_id, honeytoken_id, ts) exposures; a later exposure of the same token
by a different agent = a cascade edge; emit a propagation graph.
- **Acceptance:** two agents exposed to the same honeytoken id → exactly one cascade edge A→B with the
  time delta; distinct tokens → no edge. Reuses the honeytoken ids we already mint.

### Cross-cutting
- Fix the pytest env note (`-p no:deepeval` already in `pyproject.toml`); every new module ships with
  a runnable test. Keep `mcp_rt/` (research) and `hunt/` (product) cleanly separated.

## 4. Client collateral (the "PDF"/brief) — honesty rules

Ved asked for a client-facing brief. We will build it, but it MUST:
- **Position as a security ATTESTATION, never a certification we don't issue.** We may say
  "independently tested against the OWASP MCP Top 10 + 10 ground-truth attack classes — evidence
  attached" (the SOC2-*style* trust signal: proof of an audit). We must **NEVER** write "SOC2
  tested/certified/compliant" or imply any standard (SOC2/ISO/PCI) — those are licensed independent
  audits; claiming one is a false compliance claim, legally and reputationally fatal. Attestation = OK;
  certification claim = banned.
- **Separate Shipping from Roadmap.** Shipping = scanner, benchmark, OWASP report, daily enrich,
  consent-gated remote, public scorecard. Roadmap = CI Action (Phase 1), runtime proxy (Phase 2),
  exploit-chain correlation (Phase 2.5), cascade (Phase 3). Never present roadmap as present-tense.
- **Only verifiable numbers.** Use our real 23/26 research exfils and the live ledger denominator.
  **Do NOT** ship unverified third-party stats ("2,388 orgs", "9 of 11 directories") without a citable
  source — flag each for verification or cut it.
- **Lead with the two honest value props** (§2): fleet exposure + attestation; proxy as the roadmap wedge.
- Format: an HTML one-pager/brief artifact (shippable, on-brand), not an overclaiming slide deck.
  Build AFTER Phase 1 so "CI integration" is real when we pitch it, or clearly mark it roadmap.

## 4b. Monetization / tiering (freemium — PLANNING ONLY, build the gate on demand)

Freemium is the right model (Snyk / mate.security pattern). **PRODUCT LANGUAGE (Ved 2026-10-07): tiers
are "Basic scan" and "Advanced" / "Agent Red-Team" — NEVER "cheap"/"free-tier" adjectives in copy; use
tier NAMES.** **Hard invariant: the Basic scan must never give a false "CLEAN" — it always states which
classes it ran.** A security tool that lies about coverage destroys the zero-FP moat.

- **Basic scan (adoption + credibility — the funnel):** single-server `mcp-rt report`, the **11
  ground-truth server-side classes in full**, VAPT report, public benchmark/scorecard, CLI, open core.
- **Advanced / Agent Red-Team (what enterprises buy — maps to the roadmap above):** the **agent-in-the-
  loop MCP-00 / intent-flow (MCP06) red-team** (needs a real agent), runtime **proxy** (inline blocking),
  **CI/CD at org scale**, **continuous fleet scanning + dashboard**, **attestation/compliance reports**
  (SOC2-*style*, white-labeled), **exploit-chain correlation** ("the cash"), support/SLA.
- **Acceptable class-tiering:** novel / research-grade classes (MCP-00 / intent-flow, 0-day-grade,
  chaining) MAY be in the Advanced pack — ONLY if the Basic scan labels exactly which classes ran
  ("Basic covers 11, Advanced adds the agent red-team" is honest; a silent omission reading as CLEAN is not).
- **Architecture:** each class is a separate module → per-tier gating is a config flag, not a rewrite.
- **Do NOT build licensing machinery yet (YAGNI):** no customers, 2 findings unfiled. Gate when there's
  demand. This is Ved's lane (pricing/packaging); CTO keeps the architecture tier-ready.

## 5. Open decisions for Ved
1. **Sequence:** I recommend **Phase 1 (CI Action) first** — cheap, reuses shipping code, drives the
   adoption/visibility that's our actual bottleneck — then Phase 2 (proxy). Agree, or want the proxy first?
2. **Client brief timing:** build it now as "scanner shipping + platform roadmap", or wait until the CI
   Action is live so the pitch shows a working integration?
3. **Scope realism:** the proxy is weeks, not days, to do without corrupting traffic. Confirm that's an
   acceptable investment for the startup bet (it is the differentiator; just not a weekend job).
