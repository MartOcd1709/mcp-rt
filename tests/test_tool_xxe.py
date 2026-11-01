"""T11.2 / SAM1-22 zero-FP proof: XXE (CWE-611 file-read) + OOB/SSRF (CWE-918).

VulnerableHost resolves external entities → the victim file's per-run canary (a) and the
out-of-band collaborator fetch (b) both FIRE; SafeHost (external GES off) resolves neither →
both silent; benign no-DTD XML parses and completes on both. The oracle is pure substring /
request-log with NO XML parser in the probe path → it can't be fooled by what it tests."""
import os
import shutil

import pytest

from mcp_rt import tool_xxe as P
from tests.fixtures import xxe_hosts as H


@pytest.fixture()
def vuln():
    srv, url, tok, canary_file = H.start(vulnerable=True)
    try:
        yield url, tok, canary_file
    finally:
        srv.shutdown()
        shutil.rmtree(os.path.dirname(canary_file), ignore_errors=True)


@pytest.fixture()
def safe():
    srv, url, tok, canary_file = H.start(vulnerable=False)
    try:
        yield url, tok, canary_file
    finally:
        srv.shutdown()
        shutil.rmtree(os.path.dirname(canary_file), ignore_errors=True)


def test_vuln_file_xxe_fires(vuln):
    url, tok, cf = vuln
    assert P.probe_file_xxe(url, tok, cf)["fired"] is True

def test_vuln_oob_xxe_fires(vuln):
    url, tok, _ = vuln
    v = P.probe_oob_xxe(url, tok)
    assert v["fired"] is True and v["requested"] and v["reflected"]

def test_vuln_benign_completes(vuln):
    url, tok, _ = vuln
    v = P.probe_benign(url, tok)
    assert v["completes"] and v["fired"] is False

def test_safe_file_xxe_denied(safe):
    url, tok, cf = safe
    assert P.probe_file_xxe(url, tok, cf)["fired"] is False

def test_safe_oob_xxe_denied(safe):
    url, tok, _ = safe
    v = P.probe_oob_xxe(url, tok)
    assert v["fired"] is False and v["requested"] is False

def test_safe_benign_completes(safe):
    url, tok, _ = safe
    v = P.probe_benign(url, tok)
    assert v["completes"] and v["fired"] is False   # resilient earned: well-formed XML still parses
