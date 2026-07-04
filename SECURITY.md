# Security Policy

## Purpose and Scope

mcp-rt is an authorized security research tool. It plants synthetic credentials
(honeytokens) and observes whether an AI coding agent exfiltrates them when
connected to a deliberately malicious Model Context Protocol (MCP) server. It is
intended for defenders, researchers, and red teams assessing MCP client
security.

Use it only against agents, models, and MCP configurations that you own or are
explicitly authorized to test.

## Safety Model

- **Synthetic credentials only.** Honeytokens carry a unique per-run marker and
  are never real secrets.
- **Loopback canary.** The exfiltration listener binds to `127.0.0.1`. The
  exfil signal never leaves the local machine.
- **Automatic cleanup.** Temporary directories and the canary listener are
  destroyed after each run.

## Reporting a Vulnerability

To report a security issue in mcp-rt itself (not a finding produced *with* it),
email the maintainer at pandyaved96@gmail.com with a description and, where
possible, a minimal reproduction. Please allow a reasonable window for a fix
before public disclosure.

## Coordinated Disclosure of Findings

Findings produced with mcp-rt against third-party agents are handled under
coordinated disclosure. Affected vendors are notified privately and given time
to respond before technical details are published.
