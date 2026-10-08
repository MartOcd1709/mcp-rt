# mcp-rt MCP Security Scan — GitHub Action

Scan the MCP servers declared in your repo (`.mcp.json` / `mcp_settings.json` / `.cursor/mcp.json`)
on every pull request, with **ground-truth** detection (a planted honeytoken/sentinel/canary fired, or
it didn't — not heuristics). Results upload to the **GitHub Security tab** as SARIF; the build fails on
a critical finding so a vulnerable MCP server can't be merged.

## Usage
```yaml
# .github/workflows/mcp-security.yml
name: MCP Security
on: [pull_request]
permissions:
  security-events: write   # to upload SARIF
  contents: read
jobs:
  mcp-rt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: scan
        uses: MartOcd1709/mcp-rt/.github/action@main
        with:
          fail-on: critical          # any | critical | high | none
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcp-rt.sarif
```

## Inputs
| input | default | meaning |
|---|---|---|
| `fail-on` | `critical` | fail the build on `any` / `critical` / `high` / `none` |
| `sarif-path` | `mcp-rt.sarif` | where to write the SARIF report |
| `config` | *(auto)* | explicit config path(s); default auto-discovers MCP configs |

## Outputs
`findings-count`, `sarif-path`.

> Scans stdio MCP servers (`command`-based) locally in the runner. HTTP/url-only servers are skipped
> (use `mcp-rt remote --authorized-by` for authorized hosted scans). Nothing leaves the runner.
