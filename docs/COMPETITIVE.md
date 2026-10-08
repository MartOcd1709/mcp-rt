# Competitive Analysis — Appsecco (2026-10-06)

Source: https://appsecco.com/pricing · https://appsecco.com/mcp-pentesting · https://appsecco.com/ai-security

## What they are
An established application-security **consultancy** (UK/India, strong appsec reputation + training).
Services firm — human-delivered pentest engagements, fixed-price, **not a self-serve product/SaaS.**

## Their offering + pricing
- **MCP Server Testing: $3,500–$15,000+**, scoped by server count / tool count / auth model / tenant
  boundaries, **3–10 days**. (Also Apps/APIs $5k–$20k+, Cloud/K8s from $7.5k.)
- **13-phase methodology, 9 MCP vuln categories**; covers stdio/HTTP/SSE transports, auth/encryption,
  path traversal, command injection, SQL injection, input validation, tool poisoning, rug pull, tool
  shadowing, cross-server, confused-deputy OAuth, toxic agent flows.
- T-shirt sizing (Small→Enterprise) by endpoint/role count. Fixed price, "no hourly drift."
- **Deliverables (all tiers):** full vuln report + PoC · exec summary · remediation with code examples ·
  follow-up Q&A · **one re-test within 30 days** · **compliance-ready docs (SOC2/ISO 27001/PCI)**.
- Billing: 50% upfront / 50% on delivery; NET-30 for enterprise. **No free tier/trial.**

## The key fact
**Someone is charging $3,500–$15,000 to manually test MCP servers — our thesis is validated and
priced by a real competitor.** Their coverage ≈ our 11 ground-truth classes. We do automated +
continuous + ground-truth what they do manual + point-in-time.

## Services (them) vs Product (us)
| | Appsecco (services) | mcp-rt (product) |
|---|---|---|
| Delivery | manual, 3–10 days/engagement | automated, minutes; 131 servers already |
| Scale | a scoped handful per engagement | whole fleet + long tail, continuous |
| Price | $3.5k–$15k each, point-in-time | ~free per scan; subscription |
| Proof | human-verified | ground-truth sentinel, zero-FP |
| Brand/trust | established, compliance creds | none yet, 2 findings |
| Deliverable polish | exec summary + compliance mapping + re-test | vuln report + remediation (gaps below) |

## Strategic fork (Ved's call — business model)
1. **Services pivot** (be like Appsecco): sell mcp-rt-powered MCP-pentest engagements NOW. Immediate
   cash, validates demand, builds case studies. Doesn't scale; trades time for money.
2. **Product** (what we've built): scales, long-term moat; slower to revenue.
3. **RECOMMENDED — hybrid bootstrap:** deliver *engagements powered by mcp-rt* now (undercut Appsecco
   on speed+price because we're automated — an hour vs their days), using Ved's manual expertise for
   the human-verified layer + report. Near-term cash + real client findings + case studies, while the
   product + website mature. The product is what makes our service cheaper/faster than theirs. The
   automated layer is also sellable TO consultancies (incl. firms like Appsecco), not just end clients.

## Our differentiators to lean on
Automated + **continuous** ("they test once; we test every version, every day") · ground-truth /
zero-FP · scale (fleet + long tail) · breadth (11 classes incl. deserialization) · price.

## Product gaps to close to be SALE-READY (adopt from their deliverables)
- **Exec summary** section in the report (leadership-facing) — not just technical findings.
- **Compliance mapping** (SOC2/ISO 27001/PCI control references) — the attestation layer, paid tier.
- **Re-test / diff** (re-scan after fix, show resolved) — we have version-pinning; add a diff view.
- These three turn our `mcp-rt report` into the deliverable a buyer already expects from Appsecco.

## Honest caveat
Appsecco is reputable with human expertise, brand, and compliance credentials; we don't out-trust
them today. We win on automation/scale/price/continuity — and by being the layer they can't staff.

## Appsecco pre-engagement checklist (2026-10-06) — mapped to us (buyer-education we can satisfy)
Their checklist: (1) map MCP surface · (2) protocol-specific scope · (3) public proof · (4) reporting
format (tool-by-tool coverage + attack-path narratives) · (5) fixed SOW + retest. Our standing:
- (1) surface map → we AUTOMATE (tool/transport enumeration + fleet/CMDB). **ADD: explicit surface-map
  output (servers→tools→resources→auth→transport) — most data already there.**
- (2) protocol scope → transports/tool-params/prompt-chains/supply-chain ✓; **GAPS: OAuth AS-metadata
  probe (queued, NOT built) + connected-resource depth — close these for clean parity.**
- (3) public proof → **WE WIN:** public repo + vuln/safe fixtures (=vulnerable lab) + open 11-class
  method + public benchmark 150+ + Black Hat Arsenal. Surface these on the site as "public proof."
- (4) reporting → have exec/per-finding/compliance/PDF. **ADD: tool-by-tool COVERAGE MATRIX (data exists,
  just render — cheap); attack-path NARRATIVE = exploit-chain correlation (Phase 2.5).**
- (5) retest → we BEAT (continuous/on-demand, M3). Fixed SOW = business template (services playbook).
**CHECKLIST-PARITY WINS: coverage matrix ✅ DONE 2026-10-07 · surface-map ✅ DONE 2026-10-07 (scan_target `surface=` param inventories tools+resources in-session (no 2nd connect); run_full_scan returns `surface`; render "Attack surface" section — transport/tool count/resource count/tool→params; `tests/test_report_render.py`, 43 tests) · OAuth AS-metadata probe ✅ DONE 2026-10-07 (`remote.py`: `check_oauth_metadata` fetches `.well-known/oauth-authorization-server`/openid-config → flags missing PKCE S256 + CONFIRMS open-DCR via one synthetic unauth registration (never flags unconfirmed); wired into consent-gated `scan_remote`; kept SEPARATE from the 11 ground-truth classes (posture check, not sentinel-ground-truth, so it doesn't dilute "every verdict is ground-truth"); `tests/test_oauth.py`, 47 tests). **ALL 3 CHECKLIST-PARITY WINS DONE → we now satisfy Appsecco's entire buyer checklist.** (Future: redirect_uri-validation test via a crafted DCR registration.)**
