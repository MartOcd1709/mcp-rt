# MCP Attack-Surface Coverage Matrix — single source of truth

> GENERATED from `mcp_rt/taxonomy.py` (T5 / SAM1-17). Do not hand-edit — edit the taxonomy and regenerate.
> COVERED means a zero-FP proof exists (vuln+safe fixture/test). PARTIAL/PLANNED/N-A are shown openly;
> we never claim zero unknown-unknowns.

**Canonical items:** 68  ·  **COVERED (zero-FP):** 40 (58.8%)  ·  **PARTIAL:** 14  ·  **PLANNED:** 12  ·  **N-A:** 2

## Per-standard coverage

| Standard | items | COVERED | PARTIAL | PLANNED | N-A | unmapped |
|---|---|---|---|---|---|---|
| OWASP-MCP (https://owasp.org/www-project-mcp-top-10/) | 10 | 8 | 1 | 1 | 0 | 0 |
| ASI (https://genai.owasp.org/resource/owasp-top-10-fo) | 10 | 8 | 0 | 2 | 0 | 0 |
| CoSAI (https://www.coalitionforsecureai.org/wp-content/) | 34 | 22 | 4 | 8 | 0 | 0 |
| CIS (https://www.cisecurity.org/benchmark/ai-benchmar) | 10 | 5 | 0 | 2 | 0 | 3 |
| SPEC2026 (https://modelcontextprotocol.io/specification/20) | 13 | 7 | 1 | 5 | 0 | 0 |
| MCP38 (arXiv:2603.18063) | 38 | 25 | 9 | 4 | 0 | 0 |

## Canonical items

| id | title | status | our class | evidence / gap | external refs |
|---|---|---|---|---|---|
| ARG-INJ | Argument Injection | COVERED | arg_injection | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-07, OWASP-MCP:MCP05, CoSAI:CoSAI-21 |
| CMD-INJ | Command Injection | COVERED | command_injection | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-07, OWASP-MCP:MCP05, ASI:ASI05, CoSAI:CoSAI-21, CoSAI:CoSAI-31, CIS:CIS-9 |
| CONSENT-BYPASS | Consent / Approval Bypass + Fatigue | COVERED | permission_prompt_bypass | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-23, ASI:ASI09, CoSAI:CoSAI-13, CoSAI:CoSAI-9 |
| CONTEXT-OVERSHARE | Context Over-Sharing / Manifest Exposure | COVERED | context_oversharing | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-34, OWASP-MCP:MCP10, CoSAI:CoSAI-20 |
| CROSS-SERVER | Cross-Server Tool Poisoning | COVERED | cross_server_poisoning | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-14, ASI:ASI07, CoSAI:CoSAI-6 |
| DESER | Insecure Deserialization | COVERED | deserialization | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-09, OWASP-MCP:MCP05, ASI:ASI05, CoSAI:CoSAI-21 |
| EXFIL-CHANNELS | Data Exfiltration via Channels | COVERED | egress_evasion | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-24, MCP38:MCP-32, CoSAI:CoSAI-24, CoSAI:CoSAI-26 |
| OUTPUT-INJ | Insecure Output / Return-Value Injection | COVERED | return_value_injection | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-22, OWASP-MCP:MCP06, CoSAI:CoSAI-4 |
| P00-RESOURCE | Resource Content Injection (protocol-00) | COVERED | mcp_resource_injection | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-12, OWASP-MCP:MCP06, ASI:ASI06, CoSAI:CoSAI-4 |
| P00B-SAMPLING | Sampling Instruction Laundering (protocol-00b) | COVERED | sampling_instruction_laundering | tests/test_sampling_host.py | MCP38:MCP-20, ASI:ASI01, CoSAI:CoSAI-11 |
| P00C-ELICIT | Elicitation Credential Harvest (protocol-00c) | COVERED | elicitation_credential_harvest | tests/test_elicitation_host.py | MCP38:MCP-23, ASI:ASI09, CoSAI:CoSAI-9 |
| PARASITIC-CHAIN | Parasitic Toolchain / Workflow Exfil | COVERED | indirect_tool_chain | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-17, ASI:ASI02, CoSAI:CoSAI-24 |
| PATH-TRAV | Path Traversal / File System Exposure | COVERED | path_traversal | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-08, OWASP-MCP:MCP05, OWASP-MCP:MCP02, CoSAI:CoSAI-22, CIS:CIS-6 |
| PI-DIRECT | Prompt Injection (direct) | COVERED | prompt_template_injection | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-19, OWASP-MCP:MCP06, ASI:ASI01, CoSAI:CoSAI-11 |
| PI-INDIRECT | Prompt Injection (indirect) | COVERED | indirect_prompt_injection | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-20, OWASP-MCP:MCP06, ASI:ASI01, CoSAI:CoSAI-11 |
| PREF-MANIP | Preference Manipulation | COVERED | fake_authority_brand | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-15 |
| PRIV-ESC | Privilege Escalation / Scope Creep | COVERED | authority_injection | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-04, OWASP-MCP:MCP02, ASI:ASI03, CoSAI:CoSAI-8, CoSAI:CoSAI-20 |
| ROOTS-PATH | Roots Path Manipulation (MCP-29 ours) | COVERED | roots_path_manipulation | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-08 |
| RUG-PULL | Rug Pull / Dynamic Mutation | COVERED | rug_pull | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-16, OWASP-MCP:MCP03, ASI:ASI04, CoSAI:CoSAI-32 |
| SCHEMA-POISON | Full Schema Poisoning | COVERED | schema_examples_steering | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-11, OWASP-MCP:MCP03, CoSAI:CoSAI-3 |
| SELF-ATTEST | Tool Annotation Self-Attestation (readOnly lie) | COVERED | tool_annotation_self_attestation | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-34 |
| SPEC-CACHESCOPE | cacheScope cross-tenant cache poisoning | COVERED | mcp_rt/cachescope.py | tests/test_cachescope_poisoning.py (T10.1 — leak+poison fire via reference shared cache; s | SPEC2026:SPEC2026-cachescope, CoSAI:CoSAI-10 |
| SPEC-DOWNGRADE | Forced downgrade-to-deprecated (control bypass) | COVERED | mcp_rt/downgrade.py | tests/test_downgrade.py (T10.5 — forced-legacy bypasses the guard, modern-same-host clean; | SPEC2026:SPEC2026-downgrade, MCP38:MCP-28 |
| SPEC-HEADER-INJ | Mcp-Name header/body method differential | COVERED | mcp_rt/mcp_name_differential.py | tests/test_mcp_name_differential.py (T10.4 — authz-on-header/exec-on-body smuggle fires; s | SPEC2026:SPEC2026-mcp-name-header |
| SPEC-META-IDENTITY | _meta self-reported identity spoofing | COVERED | mcp_rt/meta_spoof.py | tests/test_meta_spoof.py (T10.3 — clientInfo/caps spoof fire; safe decides on real auth) | SPEC2026:SPEC2026-meta-identity, MCP38:MCP-01, CoSAI:CoSAI-1 |
| SPEC-REQUESTSTATE | MRTR requestState tamper + replay | COVERED | mcp_rt/mrtr_requeststate.py | tests/test_mrtr_requeststate.py (T2 — tamper/replay/cross-user fire; safe rejects; benign  | SPEC2026:SPEC2026-requeststate, CoSAI:CoSAI-17 |
| SPEC-TASKS-IDOR | Tasks handle IDOR / result-after-revoke / update-injection | COVERED | mcp_rt/task_idor.py | tests/test_task_idor.py (T10.2 — get-IDOR/revoke/update fire; safe owner-binds + re-checks | SPEC2026:SPEC2026-tasks |
| SPEC-URL-ELICIT | URL-elicitation phishing / open-redirect | COVERED | mcp_rt/url_elicitation.py | tests/test_url_elicitation.py (T10.6 — off-origin capture + pre-auth-in-URL fire; safe sam | SPEC2026:SPEC2026-url-elicitation, MCP38:MCP-23, CoSAI:CoSAI-9 |
| SQLI | SQL Injection | COVERED | sql_injection | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-09, OWASP-MCP:MCP05, CoSAI:CoSAI-21 |
| SSRF | Server-Side Request Forgery | COVERED | ssrf | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-09, OWASP-MCP:MCP05, OWASP-MCP:MCP02, CoSAI:CoSAI-26, CIS:CIS-2 |
| SSTI | Server-Side Template Injection | COVERED | ssti | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-09, OWASP-MCP:MCP05, CoSAI:CoSAI-3 |
| STRUCT-OUT | Structured-Output Resource-Link Injection (MCP-28 ours) | COVERED | structured_output_resource_link | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-12, SPEC2026:SPEC2026-requeststate |
| SUPPLY-CHAIN | Supply Chain / Dependency Tampering | COVERED | supply_chain | tests/test_supply_chain.py | MCP38:MCP-26, OWASP-MCP:MCP04, ASI:ASI04, CoSAI:CoSAI-25, CIS:CIS-8 |
| TOKEN-PASS | Token Passthrough / Confused Deputy | COVERED | token_passthrough | hunt/family_b_fixtures/{vuln,safe}_oauth_server.py + tests/test_oauth.py | MCP38:MCP-02, OWASP-MCP:MCP01, OWASP-MCP:MCP07, ASI:ASI03, CoSAI:CoSAI-16, CoSAI:CoSAI-18, CoSAI:CoSAI-8, CIS:CIS-3 |
| TOOL-POISON | Tool Description Poisoning | COVERED | tool_poisoning | hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe) | MCP38:MCP-10, OWASP-MCP:MCP03, ASI:ASI01, CoSAI:CoSAI-2 |
| TOOL-SATURATION | Tool-Count Saturation | COVERED | tool_count_saturation | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-34 |
| TOOL-SHADOW | Tool Shadowing | COVERED | tool_shadowing | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-13, CoSAI:CoSAI-5 |
| TRUST-LAUNDER | Proxy/Aggregator Trust Laundering | COVERED | proxy_aggregator_trust_laundering | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-18, ASI:ASI07, CoSAI:CoSAI-9 |
| UNDECLARED-CAP | Undeclared Capability / Consent Gap (MCP-00) | COVERED | mcp_cap | hunt/hunt_cap.py::_selftest (declared vs observed caps, reader not flagged) | MCP38:MCP-05, OWASP-MCP:MCP02, ASI:ASI02, CoSAI:CoSAI-20 |
| UNICODE-CONCEAL | Unicode / Hidden-Character Concealment | COVERED | hidden_unicode | tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none) | MCP38:MCP-11 |
| DNS-REBIND | DNS Rebinding | PARTIAL | dns_rebinding | class exists but no vuln+safe fixture located -> not COVERED until a fixture proves it zer | MCP38:MCP-31, OWASP-MCP:MCP07, CoSAI:CoSAI-26 |
| MEMORY-POISON | Memory & Context Poisoning | PARTIAL | cross_session_temporal | resource/temporal payloads touch it; persistent-memory corruption proof pending | ASI:ASI06, MCP38:MCP-12, CoSAI:CoSAI-4 |
| MISSING-AUTH | Insufficient Authentication/Authorization | PARTIAL | — | missing-auth enforcement probed; full OAuth-flow attacks pending (hunt/oauth_harness.py) [ | OWASP-MCP:MCP07, MCP38:MCP-29, CoSAI:CoSAI-18, CIS:CIS-3 |
| MISSING-INTEGRITY | Missing Integrity / Verification | PARTIAL | — | our signed attestation is the mitigation; rug_pull detects mutation; no integrity-absence  | MCP38:MCP-27, ASI:ASI04, CoSAI:CoSAI-23, CIS:CIS-8 |
| MULTI-AGENT | Multi-Agent Context / Inter-Agent Comms | PARTIAL | cross_server_poisoning | cross-server propagation partial; A2A spoofing pending | MCP38:MCP-36, ASI:ASI07, CoSAI:CoSAI-12 |
| MULTITENANCY | Improper Multitenancy | PARTIAL | — | our platform enforces org isolation (tested); not a target-server probe | MCP38:MCP-06, CoSAI:CoSAI-10 |
| MULTITURN-PLAN | Planning / Multi-Turn Agent Logic | PARTIAL | hunt-agent | authority/temporal payloads; full coverage via agent red-team + AI runtime payloads | MCP38:MCP-35, ASI:ASI01, CoSAI:CoSAI-11 |
| OVERRELIANCE | Overreliance on LLM | PARTIAL | hunt-agent | behavioral -> agent red-team (MCP06 leg 2); not a static-probe zero-FP class | MCP38:MCP-21, ASI:ASI09, CoSAI:CoSAI-7 |
| PRIVACY-INVERSION | Privacy Inversion / Cross-Session | PARTIAL | cross_session_temporal | temporal/honeytoken-alignment payloads; full multi-session proof pending | MCP38:MCP-25, ASI:ASI06, CoSAI:CoSAI-10 |
| SANDBOX-ESCAPE | Sandbox Escape | PARTIAL | — | command_injection/deserialization detect the exec primitive; sandbox-escape-specific probe | MCP38:MCP-37, ASI:ASI05 |
| SECRET-EXPOSURE | Secret / Session-Token Exposure | PARTIAL | — | we flag secret exfil via honeytoken egress; static secret-in-code scan not a class yet | OWASP-MCP:MCP01, CoSAI:CoSAI-19, CIS:CIS-6 |
| SHADOW-SERVER | Shadow MCP Servers | PARTIAL | mcp_json_supply_chain | config/supply-chain detects rogue install; live shadow-server impersonation pending [SAM1- | MCP38:MCP-18, OWASP-MCP:MCP09, CoSAI:CoSAI-6 |
| SPEC-MCP-APPS | MCP Apps UI injection (+ clickjacking/CSP/perms leads) | PARTIAL | mcp_rt/mcp_apps_ui.py | injection->executable-context is COVERED (confirmed, oracle-gated); clickjacking/UI-redres | SPEC2026:SPEC2026-mcp-apps |
| UNRESTRICTED-NET | Unrestricted Network Access | PARTIAL | network_position_delivery | delivery-position payloads; egress policy not asserted as a server finding | MCP38:MCP-32, CoSAI:CoSAI-26, CIS:CIS-9 |
| CORS | CORS / Origin Policy Bypass | PLANNED | — | no CORS/origin-policy probe [SAM1-22] | CoSAI:CoSAI-30, CIS:CIS-2 |
| CSRF | CSRF on HTTP/SSE transport | PLANNED | — | no CSRF probe for HTTP/SSE transports [SAM1-22] | CoSAI:CoSAI-29, CIS:CIS-2 |
| MITM-NOTLS | MitM / Missing TLS / Protocol Gaps | PLANNED | — | TLS-intercept capture backend exists; missing-TLS / weak-protocol not asserted as a findin | MCP38:MCP-28, OWASP-MCP:MCP07, CoSAI:CoSAI-12, CoSAI:CoSAI-27, CIS:CIS-2 |
| NO-AUDIT | Invisible Activity / No Audit Trail | PLANNED | — | server-offers-no-audit not asserted as a finding (our platform adds audit for us) [SAM1-23 | MCP38:MCP-38, OWASP-MCP:MCP08, ASI:ASI10, CoSAI:CoSAI-15, CoSAI:CoSAI-34, CIS:CIS-7 |
| RATE-DOS | Resource Exhaustion / DoS / Denial-of-Wallet | PLANNED | — | tool_count_saturation touches it; no unbounded-loop/payload-limit probe [SAM1-22] | MCP38:MCP-33, MCP38:MCP-29, CoSAI:CoSAI-14, CoSAI:CoSAI-33, ASI:ASI08, CIS:CIS-10 |
| REPLAY | Replay Attacks / Session Hijacking | PLANNED | — | no replay probe (re-send captured authed request) [SAM1-22] | MCP38:MCP-03, CoSAI:CoSAI-17, CIS:CIS-2 |
| SPEC-DISCOVER | server/discover pre-auth disclosure + downgrade oracle | PLANNED | — | unauthenticated capability/identity disclosure [SAM1-21] | SPEC2026:SPEC2026-discover |
| SPEC-LOGLEVEL | Per-request logLevel log suppression | PLANNED | — | per-request log suppression / flood control [SAM1-21] | SPEC2026:SPEC2026-loglevel, OWASP-MCP:MCP08, CoSAI:CoSAI-34 |
| SPEC-REF-SSRF | JSON-Schema $ref network dereference (SSRF/DoS) | PLANNED | — | spec warns MUST NOT auto-deref network $ref; composition-keyword DoS [SAM1-22] | SPEC2026:SPEC2026-ref-ssrf, MCP38:MCP-09 |
| SPEC-STATELESS | Stateless handle forgery / IDOR / state confusion | PLANNED | — | server-minted-handle forgery + cross-tenant state confusion under stateless transport [SAM | SPEC2026:SPEC2026-stateless, CoSAI:CoSAI-10 |
| SPEC-SUBSCRIPTIONS | subscriptionId forgery / notification injection | PLANNED | — | subscriptions/listen stream: id forgery, cross-sub leakage [SAM1-21] | SPEC2026:SPEC2026-subscriptions |
| STDIO-FD | Insecure stdio (fd leakage) / Descriptor Handling | PLANNED | — | inherited/leaked fd check over stdio not implemented [SAM1-22] | MCP38:MCP-30, CoSAI:CoSAI-28 |
| CASCADING | Cascading Failures | N-A | — | downstream pipeline blast-radius is a deployment-architecture property, not a single-serve | ASI:ASI08 |
| ROGUE-AGENT | Rogue Agents (self-directed misalignment) | N-A | — | model-alignment property of the agent, not a vulnerability of the MCP server under test | ASI:ASI10, CoSAI:CoSAI-15 |

*Standards: OWASP-MCP → https://owasp.org/www-project-mcp-top-10/ (beta 2025); ASI → https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/; CoSAI → https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf; CIS → https://www.cisecurity.org/benchmark/ai-benchmarks (MCP Server 1.0.0, WorkBench #26248); SPEC2026 → https://modelcontextprotocol.io/specification/2026-07-28/changelog; MCP38 → arXiv:2603.18063 (Shen/Toyoda/Leung) — 38 categories*
