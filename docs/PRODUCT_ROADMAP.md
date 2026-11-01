# mcp-rt — Product Roadmap & Architecture (source of truth)

> **Positioning:** the definitive **MCP-security product** — PentAGI-grade autonomous assessment *experience*, scoped to MCP, built on a **ground-truth, zero-false-positive** engine. We do not build a general pentester; we own the MCP layer and plug into general frameworks.

Author: architecture. Status: living doc — the plan every build slice is checked against.

---

## 1. Why we win (the moat, market-validated)

Research (2026) shows the MCP-security field is static-analysis-heavy and **drowning in false positives — ~78% FP on YARA-style MCP scanners** ([SecurityWall](https://securitywall.co/blog/mcp-security-testing-guide)), and the hard classes (lethal trifecta, sequence-level, Unicode concealment) are said to require human testing. The leading *autonomous* frameworks (XBOW, MAPTA) independently converge on a **validation agent / PoC-gate** — report only a reproduced exploit ([Strobes](https://strobes.co/blog/open-source-agentic-pentesting-tools/), [arXiv MAPTA](https://arxiv.org/pdf/2508.20816)).

**That is exactly our engine.** Our ground-truth oracle (plant canary → re-demonstrate with a unique nonce) is the PoC-gate, done for MCP, deterministic, since day one. So:

- **Moat = zero-FP ground-truth.** Everything we ship must preserve it. It is the one thing competitors structurally cannot copy quickly (they'd have to rebuild on ground truth).
- **Market wedge = "the MCP scanner that is right."** Our headline is a verdict you can act on, plus a clean attestation — against a field that cries wolf 78% of the time.

### Competitive map (where we lead)
| Player | Approach | Gap we exploit |
|---|---|---|
| Snyk Agent Scan (ex-Invariant mcp-scan) | static: prompt-injection, tool-poisoning, tool-pinning; flags, doesn't block | static only; no ground-truth; no exploit proof |
| Cisco MCP Scanner, Akto, Enkrypt | pre-install vetting / posture | static posture, FP-prone |
| MCP-Scanner (ICSE'26, academic) | keyword + semantic + **LLM-judge** on tools/prompts/resources | LLM-judge = FP risk; no deterministic proof |
| Browser scanners (35+ checks) | transport/auth/protocol-compliance breadth | breadth without ground-truth depth |
| XBOW / MAPTA / HexStrike | general autonomous pentest + PoC-gate | **not MCP-specialised**; we are the MCP module they lack |

Sources: [Akto](https://www.akto.io/blog/mcp-security-tools), [getmaxim](https://www.getmaxim.ai/articles/best-mcp-security-tools-in-2026/), [MCP-Scanner ICSE'26](https://dl.acm.org/doi/full/10.1145/3786160.3788471).

---

## 2. Target architecture — the complete product (6 layers)

```
┌─ DISTRIBUTION ─ CLI · CI gate (SARIF) · MCP-tool (we plug into PentAGI/CAI/Claude) · public benchmark/leaderboard
├─ EXPERIENCE ── Flow UI (create → watch live → drill to evidence) · report/PDF · signed attestation + badge
├─ PLATFORM ──── Flow model + step/reasoning trace · REST+stream(SSE) API · multi-tenant auth/RBAC/tiers · queue
├─ ORCHESTRATION Coordinator → specialists (recon/exploit) → per-target sandbox → VALIDATION (oracle) → correlate
├─ INTELLIGENCE  KG self-learning (confirmed-only) · in-house open-weights model (fine-tuned on our KG) · hypotheses
└─ ENGINE ────── 13 ground-truth classes + MCP-00/MCP-CAP/MCP-00b · honeytoken oracle (the PoC-gate) · supply-chain
```

**Build on what exists** (do not rewrite): engine, `oracle`, `knowledge` (KG), `agent_loop`+`sandbox` (ReAct+Docker), `assessment`/`pentest` (coordinator), `platform_db` (Org/ApiToken/User/RBAC/ScanRun — SQLite→Postgres), `webapp` (FastAPI + auth + job worker), `scorecard`/`stats` (single source of truth). The gap to "complete product" is the **Flow experience + scale**, not the core.

### Architecture principles (non-negotiable)
1. **Ground-truth gate on every finding** — the oracle validates; the model's say-so is never a verdict. (The moat.)
2. **Single source of truth for numbers** — `stats.json`/`CLASS_META`; no surface hardcodes a count (enforced; see `docs/DATA_MODEL.md`).
3. **Honest denominators** — SETUP_FAILED (never ran) separated from INCONCLUSIVE; nothing hidden.
4. **Deterministic rails, agentic reach** — the agent explores; deterministic probes + oracle decide.
5. **SQLite local == Postgres cloud** — same ORM; $0 local dev, scales on a box.
6. **Scoped to MCP** — breadth is MCP coverage, not network/web tooling.

---

## 3. Standards & coverage — the "don't-miss" checklist

**Align to (and publish against):**
- **OWASP MCP Top 10** — coverage map (currently 7/10 actively tested; MCP06 flagged, MCP08/09 open). *Close MCP06 (agent red-team, have), plan MCP08 telemetry / MCP09 shadow-server.*
- **OWASP APTS** (Autonomous Penetration Testing Standard) — align the flow + evaluation to it. **[RESEARCH TODO: read APTS directly, map our flow to its stages.]**
- **ATOBench / HackSynth** — verification-under-misleading-evidence eval; our oracle should score top. **[RESEARCH TODO: run and cite our zero-FP against ATOBench's premise.]**

**Attack-coverage completeness (audit vs the field — don't miss):**
- ✅ Have: command/code inj, path traversal+write, SSRF, SQLi, SSTI, arg-inj, deserialization, tool-poisoning (Unicode/TAG/zero-width/ANSI), rug-pull, token-passthrough/confused-deputy, DNS-rebinding, supply-chain (MCP04), context-oversharing (MCP10), MCP-00 (resource injection), MCP-CAP (undeclared capability), MCP-00b (sampling).
- ⚠️ **Verify/plan (named by the field, must not miss):** **lethal trifecta** (private-data + untrusted-content + exfil in one agent) — partially via MCP06 intent-flow; formalise as a named chain. **Sequence-level / multi-step** attacks — our chaining (`chains`) covers; harden. **Server impersonation / shadow-server** (MCP09). **Transport security + protocol-compliance** breadth (browser scanners do 35+ — ensure we cover TLS/origin/handshake conformance). **Elicitation (MCP-00c)** — sibling of MCP-00b, build next.
- **Discipline:** every new class ships vuln+safe fixtures and a zero-FP proof before it counts.

---

## 4. Phased roadmap

Each phase: outcome · key architecture decisions · acceptance (always includes "275+ tests green, zero-FP held").

### Phase A — Platform backbone: the Flow (foundation)
- **Outcome:** a first-class **Flow** (target → queued → running → done) that drives the full agentic assessment and **persists every step + agent reasoning + each oracle verdict** for replay/audit.
- **Decisions:** extend `platform_db` with `Flow` + `FlowStep` (not a new DB); the engine's existing `progress` callback is the step source; coordinator/validation roles named explicitly (MAPTA pattern).
- **Acceptance:** `mcp-rt flow run <target>` produces a persisted, queryable step trace ending in oracle-confirmed findings.

### Phase B — Live experience: stream + Flow UI
- **Outcome:** watch an assessment run live, PentAGI-style, then drill to the **proven payload/response per finding**.
- **Decisions:** **SSE** over the `progress` stream (FastAPI-native, simpler than WebSocket); React-free server-rendered first cut over `webapp`; evidence drill-down from the step trace.
- **Acceptance:** create a flow in the browser, see live steps, open a finding → see its ground-truth evidence + the clean/baseline.

### Phase C — Scale & robustness (borrow PentAGI)
- **Outcome:** many targets in parallel, isolated; robust with small models (alias2-mini).
- **Decisions:** **per-target ephemeral Docker sandbox + queue** (generalise `sandbox.py`+`_JOBS` into PentAGI's terminal/queue model); **mentor/supervision** layer (loop/stuck detection on top of our convergence); chain-summarisation for long runs.
- **Acceptance:** fleet of N targets runs concurrently; a stuck agent is detected and recovered; no cross-target bleed.

### Phase D — Tiers, tenancy, distribution
- **Outcome:** sellable. Basic (free, 13-class scan) vs Advanced (agent + MCP-00 + fleet) gated on existing RBAC; **MCP-tool integration** (mcp-rt callable by PentAGI/CAI/Claude as the MCP specialist); **public benchmark/leaderboard** as the citable reference suite.
- **Decisions:** reuse `platform_db` roles for tiering; expose the engine as an MCP server/tool; versioned benchmark (`v2.0`) + comparable cross-server leaderboard.
- **Acceptance:** a free user runs a basic scan; an advanced org runs the agent; an external framework invokes mcp-rt on an MCP target; the benchmark publishes a comparable grade.

### Phase E — Intelligence moat (the long game)
- **Outcome:** the data flywheel nobody else has.
- **Decisions:** KG → **in-house open-weights model fine-tuned on our confirmed-ground-truth corpus** (enterprise-acceptable: no client code to a 3rd-party API); AI raises leads, oracle confirms (confirm-principle); per-attack Docker vuln labs (public, competes with Appsecco's 157★ lab) feed the KG.
- **Acceptance:** the in-house model proposes a novel-class lead that the oracle then ground-truths.

---

## 5. Risk / don't-miss register
- **FP creep** = death. Every slice re-runs the zero-FP fixtures; any new class needs vuln+safe proof. (Market cries wolf 78%; our whole brand is that we don't.)
- **Scope drift** into general pentest — refuse; stay the MCP specialist that others plug in.
- **Model trust** — never report a model claim; oracle gates. (XBOW/MAPTA validate this is the winning pattern.)
- **Standards lag** — track OWASP MCP Top 10 revisions + APTS; the spec is young, new classes appear (we hunt MCP-00 class first → we set the checklist).
- **Open research TODOs:** read OWASP APTS + map our flow; evaluate against ATOBench premise; confirm Snyk Agent Scan / Cisco MCP Scanner exact check lists (vendor docs); formalise lethal-trifecta + shadow-server (MCP09) coverage.

---

## 6. Immediate next (this is where building starts)
**Phase A, slice 1** — the `Flow` + persisted step trace (backbone). Bounded, testable, everything else bolts on. Do not start B/C/D before A lands with zero-FP held.
