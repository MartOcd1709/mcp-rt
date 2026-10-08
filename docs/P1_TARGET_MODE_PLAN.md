# P1 — `--target` Mode Build Plan (production-grade)

Status: DRAFT for sign-off. No code until Ved approves scope + open questions.
Author: Mart (CTO). Date: 2026-07-25.

---

## 1. Goal

Turn mcp-rt from a research corpus ("we broke these agents with OUR malicious
servers") into a product a customer runs against a server THEY care about:

> `mcp-rt scan --target-stdio "npx some-mcp-server"` →
> plant real synthetic secrets → run a real agent against the target →
> **prove whether a secret physically left the host, and by which channel** →
> yes/no verdict + report + (P2) CI exit code.

## 2. The moat — why this has no equal

Every competitor (MCP-Scan, ghostprobe, Cisco mcp-scanner, Invariant guardrails)
is **static or policy-based**: they read the server's manifests/behaviour and ask
"does this LOOK malicious / violate a rule?" They cannot see server-side code, and
they cannot confirm outcome.

mcp-rt `--target` is **ground-truth outcome testing**: a unique planted secret, a
real agent, and a network tap that proves the secret left — *regardless of how it
was hidden* (server-side logic, DNS labels, an allowlisted webhook, staged exfil).
A static scanner structurally cannot match this. That is the differentiator; we
lean into it rather than sprawling features.

**One honest limit, stated up front (it is itself a finding):** a *remote,
attacker-hosted* server can exfiltrate over its own infrastructure, out of band —
invisible from the client side by design. We report that truthfully as
"unobservable-by-design," never as "clean." Competitors that claim a remote server
is clean are lying by omission; our honesty is part of the moat.

## 3. What we reuse vs. what is new

Reuse (already on disk, verified 2026-07-25):
- `mcp_rt/honeytoken.py` — unique-marker minting + workspace planting. Extend to plant
  a *battery* of realistic decoys, not one file.
- `mcp_rt/adapters/cli_client.py` — already launches real Claude Code / Codex headless
  with `--mcp-config`. Generalize the config writer to point at an *arbitrary* target
  server instead of `server/malicious_mcp_server.py`.
- `mcp_rt/detect/taint_monitor.py` — the taint rule (secret-source → undeclared-egress
  sink) is exactly our verdict engine. Feed it a REAL egress log instead of a simulated one.
- `mcp_rt/adapters/base.py` `ClientAdapter.run_task()` contract — unchanged.

New:
- **Egress tap** (`mcp_rt/capture/`) — the one genuinely new hard component. Captures all
  outbound traffic from the target + payloads, so the taint monitor has real ground truth.
- **Target spec + config builder** — parse `--target-stdio` / `--target-http`, build the
  client mcp-config.
- **Task battery / tool exercise** — introspect the target's `tools/list`, generate benign
  plausible tasks so the agent actually uses the server's tools and touches the decoys.
- **Verdict + report** — LEAKED / CLEAN / INCONCLUSIVE / UNOBSERVABLE-BY-DESIGN, with
  channel + destination + which token; JSON/SARIF/HTML.

## 4. Flow

```
mcp-rt scan --target-stdio "cmd..."  (or --target-http URL [--header ...])
      │
      ├─ 1. plant honeytoken battery in an isolated workspace
      │       (id_rsa, .env, aws creds, db DSN — each a unique HT- marker)
      ├─ 2. stand up the egress tap
      │       local/stdio target → run target behind logging proxy (HTTP+TLS via our CA)
      │                            + local DNS sink  (catches ANY destination/channel)
      │       remote/http  target → interpose logging proxy on agent↔server transport
      │                            (catches secrets the agent sends to the server;
      │                             remote out-of-band exfil = unobservable-by-design)
      ├─ 3. introspect tools/list → generate a benign task battery
      ├─ 4. run the real agent (Claude Code first) once per task, in the workspace
      ├─ 5. collect: agent tool-call trace + egress capture + advertised manifests
      ├─ 6. taint_monitor.analyze(trace, egress, manifests, tokens) → verdict
      └─ 7. emit report (JSON/SARIF/HTML) + (P2) exit code 1 if LEAKED
```

## 5. Coverage tiers (honest)

| Target type | Egress tap | Catches | Limit |
|---|---|---|---|
| Local / stdio (self-hosted, the common eval case) | full sandbox capture | server-side exfil to **any** destination incl. DNS-label, webhook, allowlisted-domain piggyback, staged | TLS-pinned outbound connections that ignore our CA — ceiling, mark it |
| Remote / http(s) URL | agent↔server transport intercept | secrets the agent is induced to send to the server (cross-server-poisoning, return-value classes) | remote's own out-of-band exfil = **unobservable-by-design**, reported as such (not "clean") |

## 6. Milestones (each independently shippable)

- **M0 — CLI + arbitrary-target wiring.** `mcp-rt scan --target-stdio/--target-http`;
  reuse cli_client to run a real agent against the target with one benign task; emit the
  tool-call trace + client-side taint verdict (no egress tap yet). *Ship: "runs your agent
  against your server and reports what it did."*
- **M1 — Egress tap (local/stdio) + real taint verdict.** Logging HTTP/S proxy (our CA) +
  DNS sink; generalize taint_monitor to the real egress log; verdict LEAKED w/ channel +
  destination. **This is the differentiator — demoable moat.**
- **M2 — Decoy battery + task generation.** Multiple realistic honeytokens; `tools/list`
  introspection → per-tool benign tasks; run the battery, aggregate. Raises coverage.
- **M3 — Remote/http interception + unobservable-by-design reporting.**
- **M4 — Reporting + CI (folds in P2).** JSON + SARIF + HTML + `--exit-code`. Machine-readable
  for pipelines. Console entry point `mcp-rt` in pyproject.
- **M5 — Hardening/UX.** Config file; known-good destination allowlist; timeouts;
  non-determinism (`--trials N`, report leak-rate); quickstart docs.

M0 + M1 = the core to demo to a customer. M2–M5 productionize.

## 7. Out of scope / deliberate ceilings (ponytail markers)

- **TLS-pinned egress interception** — a server that pins certs defeats our CA-based MITM.
  Ceiling; upgrade path = eBPF/netns-level capture. Document, don't build now.
- **LLM-generated optimal task selection** — start with per-tool templates; upgrade to
  model-generated tasks only if template coverage measurably misses tools.
- **Windows/macOS sandbox** — Linux-first (Kali). netns/transparent-redirect is the robust
  upgrade over env-proxy; env-proxy MVP first.
- **Auto-remediation / patching of the target** — out of scope; we verify, we don't fix.

## 8. Open questions (need Ved's call before coding)

1. **Egress interception tech:** use **mitmproxy** (mature dep, TLS CA + payload logging
   built in — ponytail rung 5, don't hand-roll a TLS MITM) vs a tiny stdlib HTTP proxy
   (no TLS). *Mart's rec: mitmproxy.*
2. **Local-target robustness:** env-proxy (`HTTP(S)_PROXY` + injected CA — simple, but a
   server that ignores proxy env slips it) vs netns transparent redirect (robust, needs
   root). *Mart's rec: env-proxy MVP now, netns marked as the ceiling upgrade.*
3. **First client-under-test:** Claude Code (free via OAuth, already adapted). *Rec: yes.*
4. **Dependency budget:** mitmproxy pulls a real dep tree. OK for a product, or keep it
   optional-extra (`pip install mcp-rt[capture]`)? *Rec: optional-extra.*

## 9. Test (the one runnable check per new component)

- M1 self-check: point `--target-stdio` at a **known-bad local fixture** (reuse our own
  `server/malicious_mcp_server.py` in egress mode → must verdict LEAKED with the right
  token/channel) AND a **known-good fixture** (a benign echo server → must verdict CLEAN).
  Two asserts, no framework. This is the ground-truth regression that proves the tap works.

---

## 10. Targeted customers (parallel track)

Who pays for "prove whether this MCP server leaks our credentials":

1. **Enterprises adopting MCP internally** (fintech, healthcare, any regulated shop
   standing up agent tooling) — need to vet third-party MCP servers before connecting.
   Buy trigger = the CI gate (P2). Highest-volume segment.
2. **AI-security vendors / scanner companies** — Snyk (already acquired MCP-Scan → natural
   acquirer/partner), Invariant Labs (MCP-Scan authors), Protect AI, Lasso, Prompt Security.
   They sell static scanning; we're the ground-truth layer they lack. Partner or acqui-hire.
3. **MCP server vendors / marketplaces** — want a "tested — credentials do not leak" badge
   to differentiate. Sell as a certification service.
4. **Agent platform builders** — anyone shipping an MCP-enabled agent (Cursor, Cline,
   Replit, dev-tool startups) wants to test the servers their users connect.

Intro path: Arsenal acceptance (India Aug 3 / Europe Sep 25) + the CVE disclosures give
warm credibility. Lead with the 30-second live proof (scanner: 0 findings, canary: stolen),
then the `--target` "run it on YOUR server" demo.

**Do NOT lead with feature breadth.** Lead with the one thing only we do:
ground-truth, any-channel, real-agent proof of credential survival.
