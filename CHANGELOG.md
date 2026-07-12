# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
semantic versioning.

## [Unreleased]

### Added
- Runtime taint detector (`mcp_rt/detect/`) that flags scaffolded server-side
  exfiltration by correlating a file-read source with an undeclared egress sink.
- Instruction-splitting payload family targeting resilient clients
  (`resource_split_nway`, `cross_channel_split`, `authority_resource_combo`,
  `workflow_scaffold_exfil`).
- Dedicated hunt and attack-chain runners (`attacks/run_cc_hunt.py`,
  `attacks/run_cc_chains.py`) and a detection demo (`attacks/run_detect_demo.py`).
- Test suite for the taint monitor (`tests/`).
- `attacks/run_cc_hunt.py` generalised from Claude-Code-only to `--client
  claude-code|codex|gemini`, reusing the `CodexClient` / `GeminiCLIClient` adapters
  already exercised by `attacks/run_flagship.py`; CC-Hunt task prompts added to
  `_CODEX_TASKS` and `_GEMINI_TASKS` in `mcp_rt/adapters/cli_client.py`. Codex/Gemini
  verdicts are built and ready but UNCONFIRMED — see `docs/CC_HUNT_PAYLOADS.md`.
- New payload `mcp_rt/payloads/tool_annotation_self_attestation.py` (MCP-32,
  `TOOL_ANNOTATION_SE_MODE` in `server/malicious_mcp_server.py`), the first build
  against the MCP-00d spec-gap candidate (tool annotations as unverifiable
  self-attestation) documented in `docs/SPEC_GAP_AUDIT.md` section 5, plus a
  dedicated runner `attacks/run_tool_annotation.py` (three comparison variants:
  false / accurate / none hints). Status: built, UNCONFIRMED.

## [0.1.0] - 2026-06

### Added
- Honeytoken observer harness: plant, deliver, run, verdict.
- Generation 1 attack corpus (15 payloads) and Generation 2 corpus
  (no malicious-server-install required).
- CLI adapters for Claude Code, Codex, Gemini, and Cline; mock adapter for
  key-free demos.
- Supply-chain scanner for npm MCP packages (`tools/supply_chain_scan.py`).
- Terminal, JSON, and HTML reporting.
