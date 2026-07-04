# Contributing to mcp-rt

Contributions are welcome, particularly new attack payloads and client
adapters.

## Development Setup

```bash
git clone https://github.com/vedp1712/mcp-rt
cd mcp-rt
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python -m pytest
```

## Adding a Payload

Each attack is a small class registered with `@register`. Drop a module into
`mcp_rt/payloads/` and import it in your runner; it appears in the matrix
automatically. See existing payloads for the expected interface.

## Ground-Truth Discipline

A finding is reported as `VULNERABLE` only when the planted honeytoken is
observed at the loopback canary. Do not assert a vulnerability without that
signal. Model behaviour is non-deterministic; re-run with a reset store before
citing any result, and treat a single run as provisional.

## Pull Requests

- Keep changes focused and include a short description of the attack channel or
  fix.
- Run `python -m pytest` before opening a PR.
- Do not commit real credentials, captured transcripts, or vendor disclosure
  material.

## Responsible Use

By contributing you agree that the tool is for authorized testing only. See
[SECURITY.md](SECURITY.md).
