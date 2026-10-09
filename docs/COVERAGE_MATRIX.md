# MCP Attack-Surface Coverage Matrix ("nothing missed")

**Purpose.** As a security *product* we cannot have blind spots. This living document maps the
entire **known MCP attack surface** against what mcp-rt actually tests, so every category is one of:
✅ **covered** (which payload/probe), 🟡 **partial**, or ⛔ **gap** (→ Block 0b backlog).

**Honest scope.** This is *systematically exhaustive against the documented surface* (the published
MCP-38 academic taxonomy + OWASP MCP Top 10 + our ground-truth classes), **plus a continuous process
for new threats** (threat-intel loop + AI-generated runtime payloads). It is **not** a literal
"zero gaps forever" guarantee — the threat landscape moves, and we say so.

**Baseline we ship today:** **38 attack payloads** (agent-driven corpus) + **13 ground-truth
detection classes** (direct-probe) + **MCP-00** (undeclared capability) + **OWASP MCP Top 10** mapping.

Authoritative reference: **MCP-38 taxonomy**, Shen/Toyoda/Leung, arXiv:2603.18063 (38 categories).
Note: the paper's MCP-NN numbering ≠ our internal payload numbering — this matrix maps against the
paper's authoritative list.

---

## 1. Coverage vs the published MCP-38 taxonomy (the superset)

| MCP-38 category (paper) | Status | mcp-rt test(s) |
|---|---|---|
| MCP-01 Identity Spoofing | 🟡 | missing-auth enforcement probe; spoofing per-se not asserted |
| MCP-02 Credential Theft | ✅ | **the honeytoken exfil scan itself**; `token_passthrough`; `bash_exfil_injection` |
| MCP-03 Replay Attacks | ⛔ | — no replay test |
| MCP-04 Privilege Escalation | ✅ | `authority_injection`; `permission_prompt_bypass`/`_social_eng` |
| MCP-05 Excessive Permissions | ✅ | `context_oversharing`; **MCP-00 undeclared-capability** |
| MCP-06 Improper Multitenancy | 🟡 | our *platform* enforces org isolation (tested); not a target-server probe |
| MCP-07 Command Injection | ✅✅ | `command_injection` class (CWE-78) |
| MCP-08 File System Exposure | ✅✅ | `path_traversal` class (CWE-22) |
| MCP-09 Traditional Web (SSRF/SQLi/…) | ✅✅ | `ssrf`, `sql_injection`, `ssti`, `deserialization`, `arg_injection` |
| MCP-10 Tool Description Poisoning | ✅✅ | `tool_poisoning`; `authority_injection` |
| MCP-11 Full Schema Poisoning | ✅ | `schema_examples_steering`; `hidden_unicode` |
| MCP-12 Resource Content Injection | ✅✅ | `mcp_resource_injection` v1/v2/v3; `structured_output_resource_link` |
| MCP-13 Tool Shadowing | ✅ | `tool_shadowing` |
| MCP-14 Cross-Server Tool (shadow/poison) | ✅ | `cross_server_poisoning` |
| MCP-15 Preference Manipulation | ✅ | `fake_authority_brand`; `authority_resource_combo` |
| MCP-16 Rug Pull / Dynamic Mutation | ✅✅ | `rug_pull` + **drift detection** (platform) |
| MCP-17 Parasitic Toolchain | ✅✅ | `indirect_tool_chain`; `server_side_workflow`; `workflow_scaffold_exfil` |
| MCP-18 Shadow MCP Servers | ✅ | `mcp_json_supply_chain`; `proxy_aggregator_trust_laundering` |
| MCP-19 Prompt Injection (direct) | ✅ | `prompt_template_injection` |
| MCP-20 Prompt Injection (indirect) | ✅✅ | `indirect_prompt_injection`; `return_value_prompt_injection`; `atlassian_ticket_injection` |
| MCP-21 Overreliance on LLM | 🟡 | behavioral → **agent red-team** (0c) + AI runtime payloads |
| MCP-22 Insecure Output Handling | ✅ | `return_value_injection`; `api_error_injection`; `return_value_context_injection` |
| MCP-23 Consent / Approval Bypass | ✅ | `permission_prompt_bypass`; `permission_prompt_social_eng` |
| MCP-24 Data Exfiltration via Channels | ✅✅ | `egress_evasion`; `bash_exfil_injection`; honeytoken egress tap |
| MCP-25 Privacy Inversion | ✅ | `cross_session_temporal`; `honeytoken_path_alignment` |
| MCP-26 Supply Chain | ✅✅ | `supply_chain` probe; `mcp_json_supply_chain` |
| MCP-27 Missing Integrity | ✅ | **our signed attestation is the mitigation**; `rug_pull` detects mutation |
| MCP-28 MitM / No TLS | 🟡 | TLS-intercept capture backend exists; **missing-TLS not asserted as a finding** |
| MCP-29 Protocol Gaps (rate-limit/auth) | 🟡 | missing-auth probe; **no rate-limit probe** |
| MCP-30 Insecure stdio (fd leakage) | ⛔ | — not tested |
| MCP-31 DNS Rebinding | ✅✅ | `dns_rebinding` class (CWE-346) |
| MCP-32 Unrestricted Network | ✅ | `network_position_delivery`; `egress_evasion` |
| MCP-33 Resource Exhaustion / DoS | 🟡 | `tool_count_saturation`; **no unbounded-loop/DoS probe** |
| MCP-34 Tool Manifest Exposure | ✅ | `context_oversharing`; `tool_annotation_self_attestation` |
| MCP-35 Planning / Agent Logic (multi-turn) | 🟡 | `authority_injection`, `cross_session_temporal` → **full coverage needs agent red-team + AI runtime payloads** |
| MCP-36 Multi-Agent Context | 🟡 | `cross_server_poisoning`; multi-agent propagation partial |
| MCP-37 Sandbox Escape | 🟡 | `command_injection`/`deserialization` detect exec; sandbox-escape-specific probe pending (our docker backend mitigates for *us*) |
| MCP-38 Invisible Agent Activity (no audit) | ⛔ | — not asserted as a server finding (also: *our platform* adds audit logging, security track) |

**Semantic end (MCP-07…MCP-26): dense ✅ — our 38 payloads blanket it.**
**Infra/protocol end: the gaps live here.**

## 2. Coverage vs OWASP MCP Top 10 (MCP01–MCP10)
Mapped in `hunt/report.py` (`OWASP_MCP_TOP10`, `compliance` crosswalk) — every scan emits a
PASS/FAIL per control. ✅ all ten represented by the classes above.

## 3. Ground-truth direct-probe classes (13) + MCP-00
`command_injection, path_traversal, ssrf, sql_injection, deserialization, ssti, arg_injection,
tool_poisoning, token_passthrough, rug_pull, dns_rebinding, context_oversharing, supply_chain`
— each with a **vuln+safe fixture** (must fire on vuln, stay silent on safe = zero-FP).
Plus **MCP-00** undeclared-capability hunt (strace). Plus **missing-auth enforcement** (probes).

---

## 4. Named gaps → Block 0b backlog (to fill before we claim "complete")
1. **MCP-03 Replay attacks** — add a replay probe (re-send a captured authed request).
2. **MCP-28 Missing-TLS / MitM** — flag HTTP transports without TLS as a finding; downgrade test.
3. **MCP-29/33 Rate-limiting & Resource-exhaustion (DoS)** — probe for unbounded loops / no rate limit.
4. **MCP-30 Insecure stdio (fd leakage)** — check inherited/leaked file descriptors over stdio.
5. **MCP-38 Invisible activity / no audit trail** — detect a server that offers no logging/audit hooks.
6. **Full OAuth-flow attacks** (MCP-02 subset) — wire `hunt/oauth_harness.py`: token interception,
   PKCE downgrade, redirect/discovery-URL manipulation, confused-deputy end-to-end.
7. **MCP-37 sandbox-escape-specific probe** (beyond detecting the exec primitive).
8. **MCP-35 multi-turn planning manipulation** — covered by lighting up the agent red-team (0c) +
   AI-generated runtime payloads (§5).
Each gap filled as a payload/probe with a vuln+safe fixture, then its row flips to ✅ here.

## 5. Beyond static — the engine tracks that make us not-a-blind-test (per Ved)
- **0c Agent red-team (activate):** real coding agents (Claude Code/Codex/Gemini) attempt the attacks
  → verdict = "an agent actually broke it," covers behavioral classes (MCP-21/35/36).
- **AI-generated runtime payloads (new):** an LLM mutates/synthesizes *novel* payloads per target at
  scan time (adaptive fuzzing) — catches variants the static 38 don't enumerate. Must run only in the
  hardened docker backend. Design: a `mcp_rt/payloads/ai_generator.py` that, given the target's
  tools/resources + a seed class, asks the model for candidate payloads; each is run ground-truth
  (honeytoken/canary) so a hit is still zero-FP proof, not an LLM opinion.
- **Exploit correlation (new):** chain individually-confirmed findings into a *proven* multi-step
  attack path (e.g. resource-injection → tool-chain → egress). Reuse the `chains`/`chain_steps`
  tables already in `hunt/findings_db.py` + the `attack-planner` approach; surface chains in the
  attestation + UI as the highest-severity, demonstrated result.

---

*Status: v1 (2026-10-09). Revisit whenever a new attack class, CVE, or MCP spec change lands
(threat-intel loop). Each row links to its payload/probe + vuln+safe fixture as gaps are filled.*
