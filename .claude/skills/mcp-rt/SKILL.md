---
name: mcp-rt
description: >-
  The operating manual for building and running mcp-rt — the autonomous MCP security
  lifecycle product (DISCOVER → SCAN/VA → EXPLOIT → CORRELATE → REPORT, CMDB-tracked).
  Use whenever working on mcp-rt itself: adding or deepening a module, running the
  end-to-end assessment, validating/optimizing a capability, or taking a rough feature
  to cutting-edge. Encodes the non-negotiable disciplines (ground-truth zero-FP, honest
  positioning, HITL gates, PR-not-main, session-start research, deep-per-module) and the
  validate→optimize checklist that every capability must pass before it is called done.
  Complements `mcp-hunt` (the single-server hunt loop); this is the product-wide operating
  skill. Repo root: ~/Desktop/mcp-rt.
---

# mcp-rt — product operating skill

**Thesis.** mcp-rt is the autonomous MCP security lifecycle, class of PentAGI / CSI but
MCP-specialized, with one hard edge: **ground truth.** A finding is real because the engine
*proved* it (a honeytoken fired, a canary leaked) — never because an AI "thinks so." That edge is
the moat. Every decision below protects it. Repo: `~/Desktop/mcp-rt`. Branch: `phase2-attestation-beachhead` (PR to `master`). Project state lives in memory `mcp_rt_scaling`.

## The lifecycle (the whole product is this loop)

```
DISCOVER → SCAN/VA → EXPLOIT (adaptive, ground-truth-gated) → CORRELATE → persist(CMDB) → REPORT
   │                         ▲                                      │
   └── asset inventory → DB   └──────── agent drives exploit↔correlate feedback ───┘
```

- **Deterministic rails, agentic reach.** The engine (13 ground-truth classes + MCP-00) proves what
  is real; the **agent is the depth/coverage tier** — it finds and tests what the fixed classes MISS
  and makes next-step decisions, but **every agent claim passes the same ground-truth gate** before it
  counts. Not "AI everywhere" — AI surgically, deterministic on the rails.
- **It's a loop, not a line.** Correlate reveals the next thing to test; that feeds back into exploit.

## Capability catalog — everything mcp-rt can do (one dispatcher: `mcp-rt <cmd>`)

| Stage | Command | What it does |
|---|---|---|
| Discover | `discover [--root R] [--no-localhost] [--network CIDR --authorized-by ...] [--save]` | Enumerate every MCP asset: configs (14+ clients) + packages (pip/npm/uv) + **running processes** + localhost/subnet handshake. `--save` writes each to the CMDB. Secret-redacted. |
| End-to-end | `hunt-all [--adaptive] [--execute] [--network ...] [--authorized-by ...]` | The full pipeline: discover → assess each → correlate → persist → Desktop report. |
| Assess | `assess --target-stdio "..." [--adaptive] [--execute] [--save]` | One server: scan/VA → correlate → remediate → persist. |
| Agent | `agent --target-stdio "..." [--docker] [--confirm]` | Autonomous ReAct depth tier (CSI alias2-mini). DryRun default; `--docker` hard-isolated; claims unconfirmed until ground truth. |
| Attest | `attest --target-stdio "..." [--deep] [--agent-redteam] [--verify FILE]` | Signed Ed25519 ground-truth attestation + badge, offline/in-browser verifiable. |
| Report | `assess-report [--out PATH]` | Triaged markdown from the ledger, with disclosability verdicts. |
| Scan/probe | `scan` · `probe` · `token` · `report` · `check` · `supply` | Direct protocol probes (no agent). |
| Fleet/CI | `ci [--fail-on ...] [--sarif ...]` · `fleet` · `sweep` · `daily` · `monitor` · `diff` | DevSecOps + continuous. |
| Remote | `remote --url ... --authorized-by "..."` | Consent-gated hosted-server scan. |
| Platform | `serve [--scan-backend ...]` · `org` · `registry` · `stats` · `db` | Multi-tenant SaaS + dashboard. |

## Non-negotiable disciplines (these override convenience — never trade them away)

1. **Ground truth or it doesn't count.** A finding is reported only if the engine proved it
   (canary/honeytoken). Agent/AI output is a *hypothesis* until the ground-truth gate confirms it.
   Zero false positives is the product's credibility; one FP in a disclosure burns it.
2. **Honest positioning.** Never claim "first/only/novel" without a citation. Network discovery is
   *uncommon, not unique* (shadow-mcp-scanner, Knostic, Censys exist). By-design ≠ vulnerability;
   fixtures and FPs are NEVER submitted as disclosures. The wedge is the discover→proof→attestation
   pipeline, not any single trick.
3. **HITL gates — irreversible / outward-facing only.** Require explicit authorization for: subnet
   discovery, scanning a non-local http target, disclosure/publishing. Everything reversible and
   on your own/local assets runs autonomously. Vague "HITL everywhere" is a bug.
4. **Secrets never surface.** Discovery reports env-var NAMES only; command lines are `_redact()`ed.
   The CSI key lives in chat only, never written/committed/logged (rotate after use).
5. **PR, not main.** Commit to `phase2-attestation-beachhead`; push after every commit (avoids
   conflicts); merge to `master` only when Ved says.
6. **Session-start research.** Spawn `mcp-research` each session (see memory `session-start-research`)
   for live intel + where-we-stand before deciding what to build.
7. **Deep per module, nothing missed.** Take each lifecycle module to exhaustive coverage before
   moving on; each gap is a named backlog item (`docs/COVERAGE_MATRIX.md`), not a silent hole.

## Deep-per-module process (how we take a module from rough → cutting-edge)

For each module (discover done; next = agent vuln-discovery, then correlate, then report):
1. **Enumerate the full surface** — list every source/vector/case the module must cover; name gaps.
2. **Fill the gaps** — each with a test; additive, no regressions.
3. **Align to the DB** — every artifact the module produces is recorded under the target's primary id.
4. **Validate live** — prove it on a real server, and prove the negative (it does NOT false-positive).
5. **Optimize** — speed (cheap check before expensive, bounded concurrency, caps/timeouts), cost
   (gate LLM calls), robustness (one bad target never aborts the run).
6. **Ship** — tests green (`pytest -q`), secret scan clean, commit + push to PR, update memory.

## Validate → optimize → cutting-edge checklist (run before calling any capability "done")

- [ ] **Correct**: live-proven on a real target AND a negative control (no FP). No bluffing — if it
      matched by luck (e.g. a substring), it's not done.
- [ ] **Ground-truth-gated**: nothing reported that the engine didn't prove.
- [ ] **Complete**: every source/vector enumerated; gaps named in the coverage matrix, not hidden.
- [ ] **DB-aligned**: results persisted under the primary target id; re-runs are idempotent.
- [ ] **Safe**: HITL gates on outward/irreversible actions; secrets redacted; sandboxed where it runs
      untrusted code (docker: `--rm --network none --read-only --cap-drop ALL`, limits).
- [ ] **Optimized**: bounded (timeouts, concurrency caps, LLM calls gated); one failure can't abort.
- [ ] **Tested**: a runnable check that fails if the logic breaks; full suite green.
- [ ] **Positioned honestly**: claims are citable; no by-design/FP noise in disclosures.
- [ ] **Shipped**: committed + pushed to the PR branch; memory updated.

## When a scan runs untrusted code
We execute user-supplied targets (`npx/uvx <target>`). In production the **docker backend is
mandatory** (non-root, `--network none`, `--read-only` + tmpfs, caps dropped, cpu/mem/pids limits, no
docker socket). The subprocess backend is local-dev only.
