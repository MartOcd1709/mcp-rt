# MCP Threat Intel — index

Running trail of the `mcp-research` agent's briefs (newest first). Each brief gap-checks the
latest MCP security developments against mcp-rt's corpus + probes and ranks what to build next.

- [COVERAGE_MATRIX](COVERAGE_MATRIX.md) — every known MCP attack class mapped to covered/partial/missing. The "nothing missed" reference.
- [INTEL_2026-10-05_batch2](INTEL_2026-10-05_batch2.md) — post-batch-1 gap-check (ANSI/arg-injection/DNS-rebinding now built). Top build-next: (1) OAuth AS-metadata posture probe — open DCR + redirect_uri non-validation + PKCE-not-advertised, raw-HTTP/advertised-metadata HIGH-confirmability, NOVEL vs token_passthrough, S–M; (2) harden the crude `unauthenticated_session` flag into a real no-auth tools/call verdict, S. Honest: OAuth auth-layer is the only new server-side confirmable vein a day on.
- [INTEL_2026-10-05_newclasses](INTEL_2026-10-05_newclasses.md) — new-class gap-check. Top build-next: (1) ANSI terminal-escape concealment (extends tool_poisoning, HIGH-confirmability, S), (2) argument injection / CLI flag smuggling (NOVEL, sentinel ground-truth, S–M), (3) DNS rebinding / Origin-Host validation (HTTP transport, SDK-level population, M). Deferred: cursor-traversal, cross-client leak, full-schema-poisoning (agent-only).
- [INTEL_2026-10-05](INTEL_2026-10-05.md) — seed brief. Top actions: (1) Family B token-passthrough/confused-deputy probe, (2) rug-pull detector probe, (3) investigate DuneSlide sandbox-escape (CVE-2026-50548/9). Tool-poisoning TAG-block concealment = now covered.
