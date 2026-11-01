---
name: mcp-hunt
description: >-
  Run the repeatable mcp-rt vulnerability-hunting loop against a single MCP server:
  pick a locally-installable open-source server (from mcpmarket.com, the MCP registry,
  GitHub, etc.), install it locally, scan it with mcp-rt for credential exfiltration,
  audit its code for the known bug classes, record EVERY result (vulnerable or not) in
  the findings database, and — only for a confirmed real bug — start responsible
  disclosure before anything is ever published. Use whenever Ved wants to test an MCP
  server for vulnerabilities, work through a list of servers, add a finding to the
  ledger/dashboard, or continue the hunt. Enforces the local-only + disclose-first
  guardrails that keep this legitimate.
---

# mcp-hunt — the MCP vulnerability hunt loop

The product thesis: **mate.security-style MCP security, backed by ground truth.** This
skill is the repeatable loop that fills the findings database (and later the dashboard),
one server at a time. Repo root: `~/Desktop/mcp-rt`. Field manual:
`~/Desktop/mcp-rt_field_manual.html`.

## ⭐ PRIORITY — hunt the MCP-00 family first (where the novel wins actually are)

Hard lesson (Ved, 2026-10): re-scanning the known classes + implementation bugs mostly
reproduces what the field already catalogs — **after the MCP-00 protocol-00 family we have
NOT turned up anything genuinely novel.** The 0-days that put mcp-rt's name on the
checklist have all been protocol-00: unsanitized / trust-model gaps no single vendor can
patch, only the spec can. So **lead every target with the MCP-00 lane, then fall back to
the scan/audit loop** — not the other way around.

The protocol-00 family so far (the job is to extend it, not just re-run it):
- **MCP-00** — unsanitized resource content (`audience:["assistant"]`, no sanitization req).
- **MCP-00b** — sampling instruction laundering (`sampling/createMessage`; human review is
  only a SHOULD). Exercised by `mcp_rt/adapters/sampling_host.py`.
- **MCP-00c** — elicitation credential harvest (`elicitation/create` form; no client-side
  schema classification req). Exercised by `mcp_rt/adapters/elicitation_host.py`.

**The hunt = the next sibling.** Every server-ORIGINATED or server-CONTROLLED-content
channel the spec leaves a SHOULD / undefined is a candidate: roots, structured-output /
resource-link, result `_meta`, progress-message, completion, logging, `server/discover`,
cacheable list/read. For each ask: does a headless client ingest server-controlled content
with no MUST-level gate? If yes, and no public PoC exists → that is the novel MCP-00d.

Discipline is unchanged and matters MORE here: a protocol hypothesis is NOT a finding until
a planted honeytoken fires end-to-end, proven with the **archetype host-pair** pattern —
`Vulnerable*Host` auto-trusts and fires, `Safe*Host` honours the SHOULD and holds,
`No*Host` can't declare the capability so can't reach the gap (copy `sampling_host.py` /
`elicitation_host.py`). By-design ≠ vuln: a channel a client simply ignores (our 2026-08
`_meta` / progress probe was negative cross-vendor) is an honest RESILIENT, never a
manufactured claim. Zero-FP is what makes a *novel* protocol claim credible.

## HARD GUARDRAILS — check before every target (not optional)

1. **Open-source + locally installable only.** We only test servers we can run on our own
   machine via `npx` / `pip` / `docker` / a local clone. If the only way to reach it is a
   vendor-hosted URL, STOP — that is their live service, out of scope. (`--target-http`
   returns `UNOBSERVABLE_BY_DESIGN` on purpose; never treat that as a finding.)
2. **Synthetic honeytokens only.** Already built in. Never plant or use a real credential.
3. **Loopback / local capture only.** Nothing real leaves the host; the "exfil" is caught
   by our own `LoopbackProxyBackend`.
4. **Disclose before you publish.** A confirmed real bug goes to a PRIVATE GHSA advisory
   first (Ved's proven flow). It appears on the public dashboard ONLY after it is
   disclosed/patched. Un-disclosed findings show as aggregate stats, never named.
5. **Ved runs live agent batches.** Scans that spawn the real `claude`/`codex` cost spend
   and drive a live agent — prep and verify hermetically, then hand Ved the exact command.

If any of 1–4 is in doubt for a target, record it as `SKIPPED (out of scope)` and move on.

## THE LOOP (per server)

### 1 · SELECT
Pick one candidate from a directory (mcpmarket.com / modelcontextprotocol registry /
GitHub "mcp server" topics). Capture: name, repo URL, language, install command, stars.
Prefer servers that (a) touch credentials/files/env and (b) hold an outbound channel —
those are where the `server_side_workflow` class lives. **Also note which protocol-00
capabilities it declares** (sampling / elicitation / roots / resource subscriptions) — per
the PRIORITY section, those are the first thing to probe, not an afterthought.

### 2 · SCOPE CHECK
Confirm guardrail #1 (OSS + local install). Note the install command. If it needs an API
key just to boot, use a dummy/synthetic one.

### 3 · INSTALL (locally, isolated)
Install into a throwaway dir / container. Record the exact `--target-stdio` command, e.g.
`npx -y @scope/some-mcp-server` or `python -m some_server` or `docker run ... stdio`.

### 4 · SCAN (ground truth)
```
cd ~/Desktop/mcp-rt
.venv/bin/python -m mcp_rt.scan --target-stdio "<install cmd>" --json
```
Verdict: `LEAKED` / `CLEAN` / `UNOBSERVABLE_BY_DESIGN` / `INCONCLUSIVE` (see §9 of the
field manual). `INCONCLUSIVE` = the agent never called the server's tools; retry with a
`--task` that names a tool so the agent actually exercises it.

### 5 · AUDIT (even when the scan is CLEAN — "try all the tests")
A CLEAN scan is not the end. First run the implementation-bug probes (agent-free, no spend):
```
.venv/bin/python -m hunt.probes --target-stdio "<install cmd>"
```
They test the target's own tools for SSRF (CWE-918), command/arg injection (CWE-77/78/88),
and path traversal (CWE-22) — the class behind Ved's real GHSAs — and confirm by ground
truth (loopback sink hit / sentinel file / planted canary leak). Then also:
- **Code review** the server for the known classes: argument/command injection, path
  escape / `startswith` confinement bypass, allowlist bypass, unsanitized resource
  content (MCP-00), server-side read+egress, trust-annotation self-attestation (MCP-32).
  (Ved's real GHSAs — ssh-mcp, mcp-shell-server, cli-mcp-server — all came from this.)
- Run relevant corpus payloads / a targeted manual PoC if a code path looks reachable.
- Ground-truth any suspected bug manually BEFORE claiming it (verify, don't assert).

### 6 · RECORD (always, every result)
```
.venv/bin/python -m hunt.findings_db            # one-time: create the db
```
Then log the target + scan (and audit notes) via `hunt.findings_db.DB` — see that file's
docstring. Every outcome is stored, including CLEAN and SKIPPED. Negatives are data.

### 7 · DISCLOSE (only for a confirmed real bug)
- Dedup first: search existing GHSA/CVE for the repo; a bypass of a published fix is a
  stronger report (cite the prior advisory ID).
- Draft the advisory (CWE, CVSS matched to repo precedent, root cause + PoC + structural
  fix). File PRIVATELY via GitHub Security Advisory. Record it in the `disclosures` table
  with status `reported`.
- Track status → `triaged` → `published`/`patched`. Only then flip the dashboard flag.

### 8 · SURFACE
Confirmed+disclosed findings become named dashboard rows; everything else feeds the
aggregate counts ("N servers tested, X% leak a credential to an agent"). That honest
denominator is itself the product's headline.

## DATABASE
One SQLite file now: `hunt/findings.db` (schema in `hunt/findings_db.py`, stdlib only).
Tables: `targets`, `scans`, `disclosures`. The same columns migrate to Postgres on the
VPS later — no schema change. Start local, scale when the VPS lands.

## OUTPUT DISCIPLINE
Report each server in one tight block: target → verdict → audit note → recorded? →
disclosure state. No hype. A CLEAN/RESILIENT server is a real, citable result — say so
plainly. Never inflate a count; the running total is the dashboard's number and must be
defensible line by line.
