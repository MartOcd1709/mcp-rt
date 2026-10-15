"""Master MCP Attack Taxonomy — the SINGLE SOURCE OF TRUTH for "we don't miss anything" (T5 / SAM1-17).

Every known MCP attack item, mapped to our engine class/probe with a coverage status and a zero-FP
evidence pointer. This makes completeness *provable*: every gap is visible, and the honest denominator
(PLANNED / PARTIAL / N-A shown openly) is what earns trust — we never claim zero unknown-unknowns.

Discipline (non-negotiable):
  * COVERED requires a zero-FP evidence pointer (a passing vuln+safe fixture / test). No pointer -> not COVERED.
  * Nothing is invented: external-standard items are transcribed from authoritative sources (see STANDARDS),
    and an item we can't verify or don't yet test is marked an explicit gap, never padded.
  * Static data + generation only. No target interaction.

Single-source rule (like hunt/stats.py + CLASS_META): no other surface hardcodes a class/coverage count —
they read this. `tests/test_taxonomy.py` enforces it (mirrors test_stats).

    mcp-rt taxonomy            # regenerate docs/COVERAGE_MATRIX.md + run the self-check
    mcp-rt taxonomy --check    # self-check only (CI)
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---- status enum -------------------------------------------------------------------------
COVERED = "COVERED"    # tested with a zero-FP oracle proof (evidence REQUIRED)
PARTIAL = "PARTIAL"    # some signal, but not a full zero-FP vuln+safe proof yet
PLANNED = "PLANNED"    # not tested yet; tracked to a gap ticket
NA = "N-A"             # not applicable to MCP / to a given server type (reason REQUIRED)
_STATUSES = {COVERED, PARTIAL, PLANNED, NA}


@dataclass(frozen=True)
class Item:
    id: str                              # canonical id (our scheme)
    title: str
    external_refs: tuple[str, ...]       # ids from external standards this canonical item satisfies
    our_class: str | None                # engine payload/probe name, or None if no engine class yet
    status: str
    evidence: str = ""                   # test/fixture pointer — REQUIRED when COVERED
    notes: str = ""                      # reason when PARTIAL / PLANNED / N-A
    gap_ticket: str = ""                 # SAM1-xx when PLANNED


# ---- external standards: authoritative id -> title (web-verified 2026-10-14; sources below) ----
# Each map is the *denominator* for its standard; the self-check asserts every id here is either
# referenced by >=1 taxonomy Item or listed in UNMAPPED with a reason. Titles transcribed from source.
STANDARDS: dict[str, dict] = {
    "OWASP-MCP": {  # OWASP MCP Top 10 (2025 beta) — mapped in hunt/report.py OWASP_MCP_TOP10
        "src": "https://owasp.org/www-project-mcp-top-10/ (beta 2025)",
        "items": {
            "MCP01": "Token Mismanagement and Secret Exposure",
            "MCP02": "Privilege Escalation via Scope Creep",
            "MCP03": "Tool Poisoning",
            "MCP04": "Supply Chain Attacks and Dependency Tampering",
            "MCP05": "Command Injection and Execution",
            "MCP06": "Intent Flow Subversion (Prompt Injection via Context)",
            "MCP07": "Insufficient Authentication and Authorization",
            "MCP08": "Lack of Audit and Telemetry",
            "MCP09": "Shadow MCP Servers",
            "MCP10": "Context Injection and Over Sharing",
        },
    },
    "ASI": {  # OWASP Top 10 for Agentic Applications (2026), released 2025-12-09
        "src": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
        "items": {
            "ASI01": "Agent Goal Hijack",
            "ASI02": "Tool Misuse",
            "ASI03": "Identity & Privilege Abuse",
            "ASI04": "Agentic Supply Chain Vulnerabilities",
            "ASI05": "Unexpected Code Execution",
            "ASI06": "Memory & Context Poisoning",
            "ASI07": "Insecure Inter-Agent Communication",
            "ASI08": "Cascading Failures",
            "ASI09": "Human-Agent Trust Exploitation",
            "ASI10": "Rogue Agents",
        },
    },
    "CoSAI": {  # CoSAI/OASIS MCP Security taxonomy, PGB-approved 2026-01-08. 34 atomic threats (NOT 40 — verified).
        "src": "https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf",
        "items": {  # the 34 atomic threats (tiers 1/2/3 = 7/8/19); plain integers in source, prefixed CoSAI- here
            "CoSAI-1": "Identity Spoofing", "CoSAI-2": "Tool Poisoning", "CoSAI-3": "Full Schema Poisoning",
            "CoSAI-4": "Resource Content Poisoning", "CoSAI-5": "Typosquatting/Confusion", "CoSAI-6": "Shadow MCP Servers",
            "CoSAI-7": "Overreliance on the LLM", "CoSAI-8": "Privilege Escalation via AuthN/AuthZ Bypass",
            "CoSAI-9": "Insecure Human-in-the-Loop", "CoSAI-10": "Improper Multitenancy", "CoSAI-11": "Prompt Injection",
            "CoSAI-12": "Man-in-the-Middle", "CoSAI-13": "Consent/Approval Fatigue", "CoSAI-14": "Resource Exhaustion / Denial of Wallet",
            "CoSAI-15": "Invisible Agent Activity", "CoSAI-16": "Credential/Token Theft", "CoSAI-17": "Replay Attacks / Session Hijacking",
            "CoSAI-18": "OAuth/Legacy Auth Weaknesses", "CoSAI-19": "Session Token Leakage", "CoSAI-20": "Excessive Permissions/Overexposure",
            "CoSAI-21": "Command Injection", "CoSAI-22": "File System Exposure / Path Traversal", "CoSAI-23": "Insufficient Integrity Checks",
            "CoSAI-24": "Data Exfiltration & Corruption", "CoSAI-25": "Supply Chain Compromise", "CoSAI-26": "Unrestricted Network Access",
            "CoSAI-27": "Protocol Security Gaps", "CoSAI-28": "Insecure Descriptor Handling", "CoSAI-29": "CSRF Protection Missing",
            "CoSAI-30": "CORS/Origin Policy Bypass", "CoSAI-31": "Malicious Command Execution", "CoSAI-32": "Dependency/Update Attack (rug pull)",
            "CoSAI-33": "Payload Limit / DoS", "CoSAI-34": "Lack of Observability",
        },
    },
    "CIS": {  # CIS MCP Server Benchmark v1.0.0, released 2026-09-16. 55 recs / 10 domains; domain titles verified, rec text gated.
        "src": "https://www.cisecurity.org/benchmark/ai-benchmarks (MCP Server 1.0.0, WorkBench #26248)",
        "items": {  # the 10 verified domains; the 55 individual recommendations are behind CIS registration (see UNMAPPED)
            "CIS-1": "Governance and Versioning", "CIS-2": "Transport and Connectivity",
            "CIS-3": "Authentication and Authorization", "CIS-4": "Client (Host) Configuration",
            "CIS-5": "Server Configuration", "CIS-6": "Data Protection and Privacy",
            "CIS-7": "Observability and Audit", "CIS-8": "Supply Chain Security",
            "CIS-9": "Isolation and Execution Safety", "CIS-10": "Resource Limits and Caching",
        },
    },
    "SPEC2026": {  # MCP 2026-07-28 revision — the stateless spec surface (current protocol version)
        "src": "https://modelcontextprotocol.io/specification/2026-07-28/changelog",
        "items": {
            "SPEC2026-stateless": "Stateless transport (no session id / handshake)",
            "SPEC2026-requeststate": "MRTR requestState correlation token",
            "SPEC2026-meta-identity": "_meta self-reported identity (unverified)",
            "SPEC2026-mcp-name-header": "Mcp-Name / x-mcp-header header surface",
            "SPEC2026-cachescope": "cacheScope public/private + ttlMs",
            "SPEC2026-tasks": "Tasks extension (handles, tasks/get, tasks/update)",
            "SPEC2026-mcp-apps": "MCP Apps UI extension (ui:// iframe, postMessage)",
            "SPEC2026-url-elicitation": "URL-mode elicitation (out-of-band OAuth/secret)",
            "SPEC2026-downgrade": "Protocol downgrade to Legacy / HTTP+SSE",
            "SPEC2026-discover": "server/discover pre-auth capability disclosure",
            "SPEC2026-subscriptions": "subscriptions/listen subscriptionId stream",
            "SPEC2026-ref-ssrf": "JSON-Schema $ref network dereference (SSRF/DoS)",
            "SPEC2026-loglevel": "Per-request logLevel log suppression",
        },
    },
    "MCP38": {  # MCP-38 academic taxonomy (arXiv:2603.18063) — the superset backbone we already map in COVERAGE_MATRIX.md
        "src": "arXiv:2603.18063 (Shen/Toyoda/Leung) — 38 categories",
        "items": {f"MCP-{i:02d}": t for i, t in {
            1: "Identity Spoofing", 2: "Credential Theft", 3: "Replay Attacks", 4: "Privilege Escalation",
            5: "Excessive Permissions", 6: "Improper Multitenancy", 7: "Command Injection", 8: "File System Exposure",
            9: "Traditional Web (SSRF/SQLi/...)", 10: "Tool Description Poisoning", 11: "Full Schema Poisoning",
            12: "Resource Content Injection", 13: "Tool Shadowing", 14: "Cross-Server Tool", 15: "Preference Manipulation",
            16: "Rug Pull / Dynamic Mutation", 17: "Parasitic Toolchain", 18: "Shadow MCP Servers",
            19: "Prompt Injection (direct)", 20: "Prompt Injection (indirect)", 21: "Overreliance on LLM",
            22: "Insecure Output Handling", 23: "Consent/Approval Bypass", 24: "Data Exfiltration via Channels",
            25: "Privacy Inversion", 26: "Supply Chain", 27: "Missing Integrity", 28: "MitM / No TLS",
            29: "Protocol Gaps (rate-limit/auth)", 30: "Insecure stdio (fd leakage)", 31: "DNS Rebinding",
            32: "Unrestricted Network", 33: "Resource Exhaustion / DoS", 34: "Tool Manifest Exposure",
            35: "Planning / Agent Logic (multi-turn)", 36: "Multi-Agent Context", 37: "Sandbox Escape",
            38: "Invisible Agent Activity (no audit)",
        }.items()},
    },
}

# Evidence shorthands (real, in-repo zero-FP proofs)
_PROBE = "hunt/probes.py::_selftest (vuln+safe fixtures, must fire on vuln / stay silent on safe)"
_OAUTH = "hunt/family_b_fixtures/{vuln,safe}_oauth_server.py + tests/test_oauth.py"
_AGENT = "tests/test_hunt_agent.py (MockVulnerable fires >=1 / MockSecure none)"
_CAP = "hunt/hunt_cap.py::_selftest (declared vs observed caps, reader not flagged)"

# ---- the canonical taxonomy --------------------------------------------------------------
# One record per canonical attack item. external_refs lists every standard id it satisfies, so a
# single row dedups across standards (OWASP + ASI + CoSAI + MCP38 + ... naming the same attack).
TAXONOMY: list[Item] = [
    # --- classic server-impl bugs (ground-truth probes, vuln+safe fixtures) ---
    Item("CMD-INJ", "Command Injection", ("MCP38:MCP-07", "OWASP-MCP:MCP05", "ASI:ASI05", "CoSAI:CoSAI-21", "CoSAI:CoSAI-31", "CIS:CIS-9"), "command_injection", COVERED, _PROBE),
    Item("ARG-INJ", "Argument Injection", ("MCP38:MCP-07", "OWASP-MCP:MCP05", "CoSAI:CoSAI-21"), "arg_injection", COVERED, _PROBE),
    Item("PATH-TRAV", "Path Traversal / File System Exposure", ("MCP38:MCP-08", "OWASP-MCP:MCP05", "OWASP-MCP:MCP02", "CoSAI:CoSAI-22", "CIS:CIS-6"), "path_traversal", COVERED, _PROBE),
    Item("SSRF", "Server-Side Request Forgery", ("MCP38:MCP-09", "OWASP-MCP:MCP05", "OWASP-MCP:MCP02", "CoSAI:CoSAI-26", "CIS:CIS-2"), "ssrf", COVERED, _PROBE),
    Item("SQLI", "SQL Injection", ("MCP38:MCP-09", "OWASP-MCP:MCP05", "CoSAI:CoSAI-21"), "sql_injection", COVERED, _PROBE),
    Item("SSTI", "Server-Side Template Injection", ("MCP38:MCP-09", "OWASP-MCP:MCP05", "CoSAI:CoSAI-3"), "ssti", COVERED, _PROBE),
    Item("DESER", "Insecure Deserialization", ("MCP38:MCP-09", "OWASP-MCP:MCP05", "ASI:ASI05", "CoSAI:CoSAI-21"), "deserialization", COVERED, _PROBE),
    # --- credentials / auth / access control ---
    Item("TOKEN-PASS", "Token Passthrough / Confused Deputy", ("MCP38:MCP-02", "OWASP-MCP:MCP01", "OWASP-MCP:MCP07", "ASI:ASI03", "CoSAI:CoSAI-16", "CoSAI:CoSAI-18", "CoSAI:CoSAI-8", "CIS:CIS-3"), "token_passthrough", COVERED, _OAUTH),
    Item("PRIV-ESC", "Privilege Escalation / Scope Creep", ("MCP38:MCP-04", "OWASP-MCP:MCP02", "ASI:ASI03", "CoSAI:CoSAI-8", "CoSAI:CoSAI-20"), "authority_injection", COVERED, _AGENT),
    Item("SECRET-EXPOSURE", "Secret / Session-Token Exposure", ("OWASP-MCP:MCP01", "CoSAI:CoSAI-19", "CIS:CIS-6"), None, PARTIAL, notes="we flag secret exfil via honeytoken egress; static secret-in-code scan not a class yet"),
    Item("MULTITENANCY", "Improper Multitenancy", ("MCP38:MCP-06", "CoSAI:CoSAI-10"), None, PARTIAL, notes="our platform enforces org isolation (tested); not a target-server probe"),
    Item("MISSING-AUTH", "Insufficient Authentication/Authorization", ("OWASP-MCP:MCP07", "MCP38:MCP-29", "CoSAI:CoSAI-18", "CIS:CIS-3"), None, PARTIAL, notes="missing-auth enforcement probed; full OAuth-flow attacks pending (hunt/oauth_harness.py)", gap_ticket="SAM1-15"),
    # --- tool / schema / description poisoning ---
    Item("TOOL-POISON", "Tool Description Poisoning", ("MCP38:MCP-10", "OWASP-MCP:MCP03", "ASI:ASI01", "CoSAI:CoSAI-2"), "tool_poisoning", COVERED, _PROBE),
    Item("SCHEMA-POISON", "Full Schema Poisoning", ("MCP38:MCP-11", "OWASP-MCP:MCP03", "CoSAI:CoSAI-3"), "schema_examples_steering", COVERED, _AGENT),
    Item("UNICODE-CONCEAL", "Unicode / Hidden-Character Concealment", ("MCP38:MCP-11",), "hidden_unicode", COVERED, _AGENT),
    Item("TOOL-SHADOW", "Tool Shadowing", ("MCP38:MCP-13", "CoSAI:CoSAI-5"), "tool_shadowing", COVERED, _AGENT),
    Item("CROSS-SERVER", "Cross-Server Tool Poisoning", ("MCP38:MCP-14", "ASI:ASI07", "CoSAI:CoSAI-6"), "cross_server_poisoning", COVERED, _AGENT),
    Item("PREF-MANIP", "Preference Manipulation", ("MCP38:MCP-15",), "fake_authority_brand", COVERED, _AGENT),
    Item("TOOL-SATURATION", "Tool-Count Saturation", ("MCP38:MCP-34",), "tool_count_saturation", COVERED, _AGENT),
    Item("SELF-ATTEST", "Tool Annotation Self-Attestation (readOnly lie)", ("MCP38:MCP-34",), "tool_annotation_self_attestation", COVERED, _AGENT),
    # --- prompt / intent-flow / resource injection (incl. our protocol-00 family) ---
    Item("PI-DIRECT", "Prompt Injection (direct)", ("MCP38:MCP-19", "OWASP-MCP:MCP06", "ASI:ASI01", "CoSAI:CoSAI-11"), "prompt_template_injection", COVERED, _AGENT),
    Item("PI-INDIRECT", "Prompt Injection (indirect)", ("MCP38:MCP-20", "OWASP-MCP:MCP06", "ASI:ASI01", "CoSAI:CoSAI-11"), "indirect_prompt_injection", COVERED, _AGENT),
    Item("P00-RESOURCE", "Resource Content Injection (protocol-00)", ("MCP38:MCP-12", "OWASP-MCP:MCP06", "ASI:ASI06", "CoSAI:CoSAI-4"), "mcp_resource_injection", COVERED, _AGENT, notes="MCP-00 family: attacker-controlled resource content routed to the model"),
    Item("P00B-SAMPLING", "Sampling Instruction Laundering (protocol-00b)", ("MCP38:MCP-20", "ASI:ASI01", "CoSAI:CoSAI-11"), "sampling_instruction_laundering", COVERED, "tests/test_sampling_host.py"),
    Item("P00C-ELICIT", "Elicitation Credential Harvest (protocol-00c)", ("MCP38:MCP-23", "ASI:ASI09", "CoSAI:CoSAI-9"), "elicitation_credential_harvest", COVERED, "tests/test_elicitation_host.py"),
    Item("OUTPUT-INJ", "Insecure Output / Return-Value Injection", ("MCP38:MCP-22", "OWASP-MCP:MCP06", "CoSAI:CoSAI-4"), "return_value_injection", COVERED, _AGENT),
    Item("STRUCT-OUT", "Structured-Output Resource-Link Injection (MCP-28 ours)", ("MCP38:MCP-12", "SPEC2026:SPEC2026-requeststate"), "structured_output_resource_link", COVERED, _AGENT, notes="aligns to 2026-07-28 structured output; link-handle steering"),
    Item("ROOTS-PATH", "Roots Path Manipulation (MCP-29 ours)", ("MCP38:MCP-08",), "roots_path_manipulation", COVERED, _AGENT),
    Item("CONSENT-BYPASS", "Consent / Approval Bypass + Fatigue", ("MCP38:MCP-23", "ASI:ASI09", "CoSAI:CoSAI-13", "CoSAI:CoSAI-9"), "permission_prompt_bypass", COVERED, _AGENT),
    Item("PARASITIC-CHAIN", "Parasitic Toolchain / Workflow Exfil", ("MCP38:MCP-17", "ASI:ASI02", "CoSAI:CoSAI-24"), "indirect_tool_chain", COVERED, _AGENT),
    Item("EXFIL-CHANNELS", "Data Exfiltration via Channels", ("MCP38:MCP-24", "MCP38:MCP-32", "CoSAI:CoSAI-24", "CoSAI:CoSAI-26"), "egress_evasion", COVERED, _AGENT),
    Item("PRIVACY-INVERSION", "Privacy Inversion / Cross-Session", ("MCP38:MCP-25", "ASI:ASI06", "CoSAI:CoSAI-10"), "cross_session_temporal", PARTIAL, notes="temporal/honeytoken-alignment payloads; full multi-session proof pending"),
    Item("TRUST-LAUNDER", "Proxy/Aggregator Trust Laundering", ("MCP38:MCP-18", "ASI:ASI07", "CoSAI:CoSAI-9"), "proxy_aggregator_trust_laundering", COVERED, _AGENT),
    Item("CONTEXT-OVERSHARE", "Context Over-Sharing / Manifest Exposure", ("MCP38:MCP-34", "OWASP-MCP:MCP10", "CoSAI:CoSAI-20"), "context_oversharing", COVERED, _PROBE),
    # --- undeclared capability (our MCP-00 strace hunt) ---
    Item("UNDECLARED-CAP", "Undeclared Capability / Consent Gap (MCP-00)", ("MCP38:MCP-05", "OWASP-MCP:MCP02", "ASI:ASI02", "CoSAI:CoSAI-20"), "mcp_cap", COVERED, _CAP, notes="strace sensor: declared vs observed syscalls; leads are hypotheses until confirmed"),
    # --- supply chain / integrity / rug pull ---
    Item("SUPPLY-CHAIN", "Supply Chain / Dependency Tampering", ("MCP38:MCP-26", "OWASP-MCP:MCP04", "ASI:ASI04", "CoSAI:CoSAI-25", "CIS:CIS-8"), "supply_chain", COVERED, "tests/test_supply_chain.py"),
    Item("RUG-PULL", "Rug Pull / Dynamic Mutation", ("MCP38:MCP-16", "OWASP-MCP:MCP03", "ASI:ASI04", "CoSAI:CoSAI-32"), "rug_pull", COVERED, _PROBE),
    Item("SHADOW-SERVER", "Shadow MCP Servers", ("MCP38:MCP-18", "OWASP-MCP:MCP09", "CoSAI:CoSAI-6"), "mcp_json_supply_chain", PARTIAL, notes="config/supply-chain detects rogue install; live shadow-server impersonation pending", gap_ticket="SAM1-23"),
    Item("MISSING-INTEGRITY", "Missing Integrity / Verification", ("MCP38:MCP-27", "ASI:ASI04", "CoSAI:CoSAI-23", "CIS:CIS-8"), None, PARTIAL, notes="our signed attestation is the mitigation; rug_pull detects mutation; no integrity-absence finding"),
    # --- transport / protocol / network / DoS gaps ---
    Item("MITM-NOTLS", "MitM / Missing TLS / Protocol Gaps", ("MCP38:MCP-28", "OWASP-MCP:MCP07", "CoSAI:CoSAI-12", "CoSAI:CoSAI-27", "CIS:CIS-2"), None, PLANNED, notes="TLS-intercept capture backend exists; missing-TLS / weak-protocol not asserted as a finding", gap_ticket="SAM1-22"),
    Item("REPLAY", "Replay Attacks / Session Hijacking", ("MCP38:MCP-03", "CoSAI:CoSAI-17", "CIS:CIS-2"), None, PLANNED, notes="no replay probe (re-send captured authed request)", gap_ticket="SAM1-22"),
    Item("RATE-DOS", "Resource Exhaustion / DoS / Denial-of-Wallet", ("MCP38:MCP-33", "MCP38:MCP-29", "CoSAI:CoSAI-14", "CoSAI:CoSAI-33", "ASI:ASI08", "CIS:CIS-10"), None, PLANNED, notes="tool_count_saturation touches it; no unbounded-loop/payload-limit probe", gap_ticket="SAM1-22"),
    Item("STDIO-FD", "Insecure stdio (fd leakage) / Descriptor Handling", ("MCP38:MCP-30", "CoSAI:CoSAI-28"), None, PLANNED, notes="inherited/leaked fd check over stdio not implemented", gap_ticket="SAM1-22"),
    Item("CSRF", "CSRF on HTTP/SSE transport", ("CoSAI:CoSAI-29", "CIS:CIS-2"), None, PLANNED, notes="no CSRF probe for HTTP/SSE transports", gap_ticket="SAM1-22"),
    Item("CORS", "CORS / Origin Policy Bypass", ("CoSAI:CoSAI-30", "CIS:CIS-2"), None, PLANNED, notes="no CORS/origin-policy probe", gap_ticket="SAM1-22"),
    Item("UNRESTRICTED-NET", "Unrestricted Network Access", ("MCP38:MCP-32", "CoSAI:CoSAI-26", "CIS:CIS-9"), "network_position_delivery", PARTIAL, notes="delivery-position payloads; egress policy not asserted as a server finding"),
    Item("DNS-REBIND", "DNS Rebinding", ("MCP38:MCP-31", "OWASP-MCP:MCP07", "CoSAI:CoSAI-26"), "dns_rebinding", PARTIAL, notes="class exists but no vuln+safe fixture located -> not COVERED until a fixture proves it zero-FP", gap_ticket="SAM1-22"),
    Item("NO-AUDIT", "Invisible Activity / No Audit Trail", ("MCP38:MCP-38", "OWASP-MCP:MCP08", "ASI:ASI10", "CoSAI:CoSAI-15", "CoSAI:CoSAI-34", "CIS:CIS-7"), None, PLANNED, notes="server-offers-no-audit not asserted as a finding (our platform adds audit for us)", gap_ticket="SAM1-23"),
    Item("SANDBOX-ESCAPE", "Sandbox Escape", ("MCP38:MCP-37", "ASI:ASI05"), None, PARTIAL, notes="command_injection/deserialization detect the exec primitive; sandbox-escape-specific probe pending", gap_ticket="SAM1-22"),
    # --- behavioral / multi-agent (need the agent red-team, MCP06 leg 2) ---
    Item("OVERRELIANCE", "Overreliance on LLM", ("MCP38:MCP-21", "ASI:ASI09", "CoSAI:CoSAI-7"), "hunt-agent", PARTIAL, notes="behavioral -> agent red-team (MCP06 leg 2); not a static-probe zero-FP class"),
    Item("MULTITURN-PLAN", "Planning / Multi-Turn Agent Logic", ("MCP38:MCP-35", "ASI:ASI01", "CoSAI:CoSAI-11"), "hunt-agent", PARTIAL, notes="authority/temporal payloads; full coverage via agent red-team + AI runtime payloads"),
    Item("MULTI-AGENT", "Multi-Agent Context / Inter-Agent Comms", ("MCP38:MCP-36", "ASI:ASI07", "CoSAI:CoSAI-12"), "cross_server_poisoning", PARTIAL, notes="cross-server propagation partial; A2A spoofing pending"),
    Item("MEMORY-POISON", "Memory & Context Poisoning", ("ASI:ASI06", "MCP38:MCP-12", "CoSAI:CoSAI-4"), "cross_session_temporal", PARTIAL, notes="resource/temporal payloads touch it; persistent-memory corruption proof pending"),
    Item("CASCADING", "Cascading Failures", ("ASI:ASI08",), None, NA, notes="downstream pipeline blast-radius is a deployment-architecture property, not a single-server attack we can ground-truth"),
    Item("ROGUE-AGENT", "Rogue Agents (self-directed misalignment)", ("ASI:ASI10", "CoSAI:CoSAI-15"), None, NA, notes="model-alignment property of the agent, not a vulnerability of the MCP server under test"),
    # --- 2026-07-28 stateless spec surface (new; the T10 pack) ---
    Item("SPEC-STATELESS", "Stateless handle forgery / IDOR / state confusion", ("SPEC2026:SPEC2026-stateless", "CoSAI:CoSAI-10"), None, PLANNED, notes="server-minted-handle forgery + cross-tenant state confusion under stateless transport", gap_ticket="SAM1-21"),
    Item("SPEC-REQUESTSTATE", "MRTR requestState tamper + replay", ("SPEC2026:SPEC2026-requeststate", "CoSAI:CoSAI-17"), "mcp_rt/mrtr_requeststate.py", COVERED, evidence="tests/test_mrtr_requeststate.py (T2 — tamper/replay/cross-user fire; safe rejects; benign completes)"),
    Item("SPEC-META-IDENTITY", "_meta self-reported identity spoofing", ("SPEC2026:SPEC2026-meta-identity", "MCP38:MCP-01", "CoSAI:CoSAI-1"), "mcp_rt/meta_spoof.py", COVERED, evidence="tests/test_meta_spoof.py (T10.3 — clientInfo/caps spoof fire; safe decides on real auth)"),
    Item("SPEC-HEADER-INJ", "Mcp-Name header/body method differential", ("SPEC2026:SPEC2026-mcp-name-header",), "mcp_rt/mcp_name_differential.py", COVERED, evidence="tests/test_mcp_name_differential.py (T10.4 — authz-on-header/exec-on-body smuggle fires; safe -32020; MUST-violation)"),
    Item("SPEC-CACHESCOPE", "cacheScope cross-tenant cache poisoning", ("SPEC2026:SPEC2026-cachescope", "CoSAI:CoSAI-10"), "mcp_rt/cachescope.py", COVERED, evidence="tests/test_cachescope_poisoning.py (T10.1 — leak+poison fire via reference shared cache; safe private)"),
    Item("SPEC-TASKS-IDOR", "Tasks handle IDOR / result-after-revoke / update-injection", ("SPEC2026:SPEC2026-tasks",), "mcp_rt/task_idor.py", COVERED, evidence="tests/test_task_idor.py (T10.2 — get-IDOR/revoke/update fire; safe owner-binds + re-checks)"),
    Item("SPEC-MCP-APPS", "MCP Apps UI injection (+ clickjacking/CSP/perms leads)", ("SPEC2026:SPEC2026-mcp-apps",), "mcp_rt/mcp_apps_ui.py", PARTIAL, evidence="tests/test_mcp_apps_ui.py (T10.7 — UI markup injection CONFIRMED)", notes="injection->executable-context is COVERED (confirmed, oracle-gated); clickjacking/UI-redress, permissive CSP, over-broad permissions, postMessage/sandbox-escape remain labeled UNCONFIRMED leads (no deterministic sink) -> PARTIAL, not COVERED", gap_ticket="SAM1-21"),
    Item("SPEC-URL-ELICIT", "URL-elicitation phishing / open-redirect", ("SPEC2026:SPEC2026-url-elicitation", "MCP38:MCP-23", "CoSAI:CoSAI-9"), "mcp_rt/url_elicitation.py", COVERED, evidence="tests/test_url_elicitation.py (T10.6 — off-origin capture + pre-auth-in-URL fire; safe same-origin to server)"),
    Item("SPEC-DOWNGRADE", "Forced downgrade-to-deprecated (control bypass)", ("SPEC2026:SPEC2026-downgrade", "MCP38:MCP-28"), "mcp_rt/downgrade.py", COVERED, evidence="tests/test_downgrade.py (T10.5 — forced-legacy bypasses the guard, modern-same-host clean; safe uniform)"),
    Item("SPEC-DISCOVER", "server/discover pre-auth disclosure + downgrade oracle", ("SPEC2026:SPEC2026-discover",), None, PLANNED, notes="unauthenticated capability/identity disclosure", gap_ticket="SAM1-21"),
    Item("SPEC-SUBSCRIPTIONS", "subscriptionId forgery / notification injection", ("SPEC2026:SPEC2026-subscriptions",), None, PLANNED, notes="subscriptions/listen stream: id forgery, cross-sub leakage", gap_ticket="SAM1-21"),
    Item("SPEC-REF-SSRF", "JSON-Schema $ref network dereference (SSRF/DoS)", ("SPEC2026:SPEC2026-ref-ssrf", "MCP38:MCP-09"), None, PLANNED, notes="spec warns MUST NOT auto-deref network $ref; composition-keyword DoS", gap_ticket="SAM1-22"),
    Item("SPEC-LOGLEVEL", "Per-request logLevel log suppression", ("SPEC2026:SPEC2026-loglevel", "OWASP-MCP:MCP08", "CoSAI:CoSAI-34"), None, PLANNED, notes="per-request log suppression / flood control", gap_ticket="SAM1-21"),
]

# ---- explicit non-mappings (honest denominators) -----------------------------------------
# A standard id here is consciously NOT a distinct taxonomy row, with a reason. The self-check
# treats these as accounted-for (so the denominator stays honest without inventing rows).
UNMAPPED: dict[str, str] = {
    # CIS v1.0.0: only the 10 domains are public; the 55 individual recommendations are behind CIS
    # registration. We anchor at domain level; recommendation-level granularity is a tracked gap.
    "CIS:CIS-1": "domain-level only (Governance/Versioning) — lifecycle/version hygiene is process, not a server-probe; 55 recs gated, pending the CIS PDF",
    "CIS:CIS-4": "domain-level only (Client/Host Config) — hardening of the consuming host, not the target server we scan",
    "CIS:CIS-5": "domain-level only (Server Config) — spans many rows (auth/isolation/limits); mapped via those, recs gated",
    "CIS:CIS-7": "domain-level: Observability/Audit — see NO-AUDIT (PLANNED); 55 recs gated",
}


# ---- derivations + generation ------------------------------------------------------------
def _all_refs() -> set[str]:
    refs: set[str] = set()
    for it in TAXONOMY:
        refs.update(it.external_refs)
    return refs


def coverage() -> dict:
    """Canonical coverage figures. Everything downstream reads this — no parallel counting."""
    by_status: dict[str, int] = {s: 0 for s in _STATUSES}
    for it in TAXONOMY:
        by_status[it.status] += 1
    total = len(TAXONOMY)
    tested = by_status[COVERED]
    # "assessed" = covered or explicitly not-applicable (honest: PARTIAL/PLANNED are open work)
    return {
        "total_items": total,
        "by_status": by_status,
        "covered_pct": round(100 * tested / total, 1) if total else 0.0,
        "standards": {name: len(s["items"]) for name, s in STANDARDS.items()},
    }


def by_standard() -> dict:
    """Per-standard: how many of its items are referenced by a COVERED / PARTIAL / other row."""
    out: dict[str, dict] = {}
    status_of = {}
    for it in TAXONOMY:
        for r in it.external_refs:
            # keep the best status seen for a given external ref
            prev = status_of.get(r)
            rank = {COVERED: 3, PARTIAL: 2, PLANNED: 1, NA: 0}
            if prev is None or rank[it.status] > rank[prev]:
                status_of[r] = it.status
    for name, s in STANDARDS.items():
        counts = {COVERED: 0, PARTIAL: 0, PLANNED: 0, NA: 0, "unmapped": 0}
        for iid in s["items"]:
            ref = f"{name}:{iid}"
            if ref in status_of:
                counts[status_of[ref]] += 1
            elif ref in UNMAPPED:
                counts["unmapped"] += 1
            else:
                counts["unmapped"] += 1
        out[name] = counts
    return out


def render_markdown() -> str:
    cov = coverage()
    bs = by_standard()
    L = ["# MCP Attack-Surface Coverage Matrix — single source of truth",
         "",
         "> GENERATED from `mcp_rt/taxonomy.py` (T5 / SAM1-17). Do not hand-edit — edit the taxonomy and regenerate.",
         "> COVERED means a zero-FP proof exists (vuln+safe fixture/test). PARTIAL/PLANNED/N-A are shown openly;",
         "> we never claim zero unknown-unknowns.",
         "",
         f"**Canonical items:** {cov['total_items']}  ·  "
         f"**COVERED (zero-FP):** {cov['by_status'][COVERED]} ({cov['covered_pct']}%)  ·  "
         f"**PARTIAL:** {cov['by_status'][PARTIAL]}  ·  **PLANNED:** {cov['by_status'][PLANNED]}  ·  **N-A:** {cov['by_status'][NA]}",
         "",
         "## Per-standard coverage",
         "",
         "| Standard | items | COVERED | PARTIAL | PLANNED | N-A | unmapped |",
         "|---|---|---|---|---|---|---|"]
    for name, s in STANDARDS.items():
        c = bs[name]
        L.append(f"| {name} ({s['src'].split(' ')[0][:48]}) | {len(s['items'])} | "
                 f"{c[COVERED]} | {c[PARTIAL]} | {c[PLANNED]} | {c[NA]} | {c['unmapped']} |")
    L += ["", "## Canonical items", "",
          "| id | title | status | our class | evidence / gap | external refs |",
          "|---|---|---|---|---|---|"]
    rank = {COVERED: 0, PARTIAL: 1, PLANNED: 2, NA: 3}
    for it in sorted(TAXONOMY, key=lambda i: (rank[i.status], i.id)):
        eg = it.evidence if it.status == COVERED else (it.notes + (f" [{it.gap_ticket}]" if it.gap_ticket else ""))
        L.append(f"| {it.id} | {it.title} | {it.status} | {it.our_class or '—'} | {eg[:90]} | {', '.join(it.external_refs)} |")
    L += ["", f"*Standards: " + "; ".join(f"{n} → {s['src']}" for n, s in STANDARDS.items()) + "*", ""]
    return "\n".join(L)


# ---- self-check (assert-based; CI calls this) --------------------------------------------
def selfcheck() -> list[str]:
    """Return a list of problems (empty == healthy). Enforces the non-negotiables."""
    problems: list[str] = []
    seen_ids: set[str] = set()
    for it in TAXONOMY:
        if it.status not in _STATUSES:
            problems.append(f"{it.id}: bad status {it.status!r}")
        if it.id in seen_ids:
            problems.append(f"{it.id}: duplicate canonical id")
        seen_ids.add(it.id)
        # the moat: COVERED requires a real evidence pointer
        if it.status == COVERED and not it.evidence.strip():
            problems.append(f"{it.id}: COVERED but no evidence pointer")
        # honesty: PARTIAL/PLANNED/N-A must say why
        if it.status in (PARTIAL, PLANNED, NA) and not it.notes.strip():
            problems.append(f"{it.id}: {it.status} but no notes/reason")
        # every external ref must name a real standard + id
        for r in it.external_refs:
            std, _, iid = r.partition(":")
            if std not in STANDARDS:
                problems.append(f"{it.id}: ref {r} names unknown standard")
            elif iid not in STANDARDS[std]["items"]:
                problems.append(f"{it.id}: ref {r} not an id in {std}")
    # completeness: every external-standard item is referenced or explicitly UNMAPPED
    refs = _all_refs()
    for name, s in STANDARDS.items():
        for iid in s["items"]:
            ref = f"{name}:{iid}"
            if ref not in refs and ref not in UNMAPPED:
                problems.append(f"UNCOVERED standard item (no row, not UNMAPPED): {ref} — {s['items'][iid]}")
    # single-source: the printed count must equal the matrix length
    if coverage()["total_items"] != len(TAXONOMY):
        problems.append("coverage().total_items != len(TAXONOMY)")
    # reconcile with reality: every live detection class (CLASS_META) must appear as an our_class
    # here, so a class can never exist in the engine yet be silently missing from the taxonomy.
    try:
        from hunt.report import CLASS_META
        mapped = {it.our_class for it in TAXONOMY if it.our_class}
        for cls in CLASS_META:
            if cls not in mapped:
                problems.append(f"detection class {cls!r} (CLASS_META) has no taxonomy row")
    except Exception as e:  # noqa: BLE001 — reconciliation is best-effort if report import fails
        problems.append(f"could not reconcile against CLASS_META: {type(e).__name__}: {e}")
    return problems


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="mcp-rt taxonomy", description="Master MCP attack taxonomy / coverage source of truth")
    p.add_argument("--check", action="store_true", help="run the self-check only (CI); exit 1 on any problem")
    p.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "docs" / "COVERAGE_MATRIX.md"),
                   help="where to write the generated markdown page")
    args = p.parse_args(argv)
    problems = selfcheck()
    if problems:
        print("taxonomy self-check FAILED:")
        for pr in problems:
            print("  -", pr)
        return 1
    cov = coverage()
    print(f"taxonomy self-check OK — {cov['total_items']} items, "
          f"{cov['by_status'][COVERED]} COVERED ({cov['covered_pct']}%), "
          f"{cov['by_status'][PARTIAL]} PARTIAL, {cov['by_status'][PLANNED]} PLANNED, {cov['by_status'][NA]} N-A")
    if not args.check:
        Path(args.out).write_text(render_markdown(), encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
