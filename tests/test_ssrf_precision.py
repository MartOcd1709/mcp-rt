"""SSRF probe precision: a declared fetcher reaching a URL is by-design, not SSRF.

Regression for the mcp-server-fetch false-positive — its tool is literally named `fetch`, which the
phrase-based _DEDICATED_FETCH missed. A non-fetch tool steered to internal hosts is still SSRF.
"""
from hunt.probes import _DEDICATED_FETCH, _FETCH_NAME


def _dedicated(name, desc=""):
    return bool(_DEDICATED_FETCH.search(desc + " " + name) or _FETCH_NAME.search(name))


def test_declared_fetchers_are_by_design():
    assert _dedicated("fetch", "Fetches a URL from the Internet and extracts contents")   # the FP case
    assert _dedicated("curl") and _dedicated("download_file", "Download a file from a url")
    assert _dedicated("web_search", "search the web") and _dedicated("http_get")


def test_non_fetchers_still_flag_ssrf():
    assert not _dedicated("get_project_metrics", "fetch analytics for the workspace")
    assert not _dedicated("read_ticket", "read a jira ticket")
    assert not _dedicated("summarize", "summarize a document")
