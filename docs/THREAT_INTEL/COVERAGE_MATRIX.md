# MCP attack-class coverage matrix — 2026-10-05

Union of every known MCP attack class across the public taxonomies, mapped to mcp-rt's
coverage so nothing is missed. Sources: [MCP-38](https://arxiv.org/pdf/2603.18063),
[OWASP MCP Top 10](https://cycode.com/blog/owasp-mcp-top-10/),
[CSAI](https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf),
[arXiv landscape taxonomy](https://arxiv.org/html/2503.23278v3),
[When MCP Servers Attack](https://arxiv.org/pdf/2509.24272).

Legend: ✅ covered · 🟡 partial · ❌ missing. "Probe" = active Mode-B detector in `hunt.probes`.

## Semantic / model-facing (Mode A attack corpus)
| Class | Status | Where |
|---|---|---|
| Tool poisoning (description/schema) | ✅ | MCP-01 + `tool_poisoning` probe |
| Unicode TAG / invisible-char / ANSI-escape concealment | ✅ | `tool_poisoning` probe (TAG+zero-width+bidi+ANSI) |
| Cross-server shadowing / poisoning | ✅ | MCP-19 |
| Tool shadowing / name conflict | ✅ | MCP-12 |
| Indirect prompt injection (file/web) | ✅ | MCP-18 / MCP-20 |
| Resource-channel injection (MCP-00) | ✅ | MCP-00, MCP-17 |
| Parasitic tool chaining | ✅ | indirect_tool_chain |
| Sampling / elicitation / roots / structured-output (2025) | ✅ | MCP-26/27/28/29 |
| Server-side workflow exfil | ✅ | MCP-09 |
| Egress-control evasion (webhook/DNS) | ✅ | MCP-34 |
| Preference manipulation (biased tool selection) | 🟡 | MCP-16 (brand/authority) — no dedicated test |
| Rug pull / dynamic trust violation | ✅ | `rug_pull` detector probe (NEW) — in-session tool-def mutation |

## Implementation bugs (Mode B probes)
| Class | Status | Where |
|---|---|---|
| Command / STDIO injection (+ allowlist bypass) | ✅ | `command_injection` probe |
| Code / eval injection (python/node) | ✅ | `command_injection` eval payloads |
| Argument injection / CLI flag smuggling | ✅ | `arg_injection` probe (NEW) — flag-effect ground truth |
| SSRF (+ internal/metadata + redirect-follow) | ✅ | `ssrf` probe |
| Path traversal (read) | ✅ | `path_traversal` probe |
| Arbitrary file write (write-escape) | ✅ | `path_traversal` probe |
| SQL injection (error-based) | ✅ | `sql_injection` probe (NEW) |
| DoS / tool-count saturation | ✅ (refuted) | MCP-31 negative |
| SSTI (template injection) | ✅ | `ssti` probe (NEW) — 1337×1337 marker arithmetic |
| XXE (XML external entity) | ❌ | niche: XML-parsing tools |
| Insecure deserialization | ❌ | niche |
| Sandbox escape (DuneSlide CVE-2026-50548/9) | ❌ | hard to probe generically — hunt-signature |

## Identity / auth / access (OWASP MCP01/02)
| Class | Status | Where |
|---|---|---|
| Token mismanagement / secret exposure | 🟡 | scan exfil detection catches a leaked planted secret |
| OAuth token passthrough / confused deputy | ✅ | `hunt.family_b` — OAuth harness + `token_passthrough` probe (NEW) |
| Privilege escalation / scope creep | ❌ | hard generic probe |
| Unauthorized access / session hijack | ❌ | needs auth context |

## Supply chain / delivery / ops
| Class | Status | Where |
|---|---|---|
| `.mcp.json` auto-load / zero-install | ✅ | MCP-20 |
| Network-position substitution / rogue resolver | 🟡 | MCP-33 (inconclusive) |
| Typosquat / namespace / installer spoof / rogue registration | 🟡 | delivery research — no active test |
| DNS rebinding / missing Origin+Host validation | ✅ | `remote.py` Origin-validation check (NEW) — raw-HTTP 403 ground truth |
| Re-deploy vulnerable version / config drift / post-update persistence | ❌ | posture scan, not an active probe |

## Net: what to build next (ranked)
1. ✅ **OAuth token passthrough / confused deputy** — DONE (`hunt.family_b`, verified).
2. **Rug-pull detector** — re-list tools over time, diff descriptions/schemas. Buildable, agent-free.
3. **SSTI probe** — marker arithmetic (`{{7*7}}`→49) ground truth; quick add to the engine.
4. **DuneSlide sandbox-escape** — investigate as a hunt-signature / dedicated class.
5. **Unified VAPT report + compliance mapping** (the product layer — see below).
