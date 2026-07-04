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

## [0.1.0] - 2026-06

### Added
- Honeytoken observer harness: plant, deliver, run, verdict.
- Generation 1 attack corpus (15 payloads) and Generation 2 corpus
  (no malicious-server-install required).
- CLI adapters for Claude Code, Codex, Gemini, and Cline; mock adapter for
  key-free demos.
- Supply-chain scanner for npm MCP packages (`tools/supply_chain_scan.py`).
- Terminal, JSON, and HTML reporting.
