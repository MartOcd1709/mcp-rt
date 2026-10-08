"""Discovery plumbing-filter: infra packages excluded, real tool servers kept (no network)."""
from hunt.sweep import _RISKY, _SKIP_SUBSTR


def _skipped(name: str) -> bool:
    return any(x in name.lower() for x in _SKIP_SUBSTR)


def test_infra_plumbing_excluded():
    for n in ("mcp-proxy", "mcp-handler", "@ag-ui/mcp-middleware",
              "some-sdk-mcp", "mcp-gateway", "mcp-inspector"):
        assert _skipped(n), f"{n} should be filtered as plumbing"


def test_real_tool_servers_kept():
    # These must NOT be excluded — the broad tokens (porter/ui/remote/bridge) we deliberately
    # left out would wrongly catch exporter / builder / remote-shell / file-bridge.
    for n in ("mcp-ssh-terminal", "d33naz-mcp-filesystem", "data-exporter-mcp",
              "builder-mcp", "remote-shell-mcp", "codepage-bridge-mcp", "mcp-sqlite"):
        assert not _skipped(n), f"{n} is a real tool server, must not be filtered"


def test_risky_covers_widened_categories():
    # the new injection-prone categories must qualify (matched on name or description)
    for n in ("postgres-mcp", "mcp-mysql", "mongodb-mcp", "mcp-redis", "mcp-playwright",
              "puppeteer-mcp", "mcp-scrape", "docker-mcp", "mcp-kubernetes", "s3-mcp", "mcp-pdf"):
        assert _RISKY.search(n), f"{n} should qualify as risky"
    # short tokens are word-bounded so they don't false-match inside unrelated words
    for n in ("flaws-mcp", "mcp-useless"):   # 'aws' in flaws, 's3' nowhere — must NOT match on these
        assert not _RISKY.search(n), f"{n} should NOT spuriously qualify"
