"""SSRF probe precision: reaching a caller-supplied URL is by-design only when THAT is the tool's job.

An oracle firing (the loopback sink was reached) proves the EFFECT, not a vulnerability. The by-design
control reads the tool's declared surface (name + description) and asks whether accessing the URL is its
primary function. Ved-signed case matrix (#22):
  1. navigate / goto / open / visit / browse / load a URL        -> by_design
  2. dedicated fetch / curl / request / download                 -> by_design
  3. UNRELATED purpose (summarize/notify/convert/store) that fetches -> SSRF (must NOT regress)
  4. screenshot / pdf OF a URL                                   -> by_design
The discriminator is derived from the declared purpose, not a fixed tool-name allowlist; the name-free
test proves it generalizes to tool names that are not in hunt/probes.py.
"""
import random
import secrets
from pathlib import Path

from hunt.probes import _url_access_by_design

REPO = Path(__file__).resolve().parents[1]


def by_design(name, desc=""):
    return _url_access_by_design(name, desc)


# Case 2 — dedicated fetchers (the prior behavior, kept)
def test_dedicated_fetchers_are_by_design():
    assert by_design("fetch", "Fetches a URL from the Internet and extracts contents")   # the mcp-server-fetch FP
    assert by_design("curl") and by_design("download_file", "Download a file from a url")
    assert by_design("web_search", "search the web") and by_design("http_get")


# Case 1 — navigation
def test_navigation_tools_are_by_design():
    assert by_design("browser_navigate", "Navigate the browser to a URL")
    assert by_design("goto", "Go to a page")
    assert by_design("open_url", "Open the given website")
    assert by_design("visit", "Visit a URL and return the DOM")
    assert by_design("load_page", "Load the page at the given url")


# Case 4 — render / screenshot / pdf OF a url
def test_render_and_capture_tools_are_by_design():
    assert by_design("screenshot", "Take a screenshot of a web page")
    assert by_design("capture", "Capture a snapshot of the url")
    assert by_design("to_pdf", "Render the web page to pdf")
    assert by_design("url2pdf", "Convert a webpage to pdf")
    assert by_design("render_page", "Render the page at the URL")


# Case 3 — a data operation that merely fetches is still SSRF (must NOT regress into by-design)
def test_data_operations_that_fetch_still_flag_ssrf():
    assert not by_design("summarize", "Summarize the document at the given URL")
    assert not by_design("notify", "Send a notification to the given webhook url")
    assert not by_design("convert_doc", "Convert the document to markdown")
    assert not by_design("store_record", "Store the record at the destination url")
    assert not by_design("analyze", "Analyze the content of a page")
    assert not by_design("get_project_metrics", "fetch analytics for the workspace")   # 'fetch' as a data verb
    assert not by_design("read_ticket", "read a jira ticket")


# Generalization: names NOT present in the probe source must classify by purpose, not by a hardcoded list.
_ACCESS = ["Navigate to the {n}", "Open the {n}", "Load the {n}", "Fetch the contents of the {n}",
           "Take a screenshot of the {n}", "Render the {n} to pdf", "Visit the {n} and return its DOM",
           "Download the file at the {n}", "Proxy requests to the {n}"]
_DATAOP = ["Summarize the {n}", "Classify the {n}", "Translate the {n}", "Store the {n} in the database",
           "Notify the team about the {n}", "Count the words on the {n}", "Extract entities from the {n}"]
_NOUNS = ["url", "page", "website", "web page", "link", "address"]


def _rand_name():
    # a plausible tool name with NO access/data verb token, so only the description decides
    return random.choice(["widget", "entry", "record", "item", "node", "unit"]) + "_" + secrets.token_hex(3)


def test_name_free_access_descriptions_are_by_design_and_data_ops_are_not():
    src = (REPO / "hunt" / "probes.py").read_text()
    rng = random.Random(secrets.randbits(32))
    for _ in range(12):
        name = _rand_name()
        assert name not in src                       # the proof is purpose-derived, not name-matched
        noun = rng.choice(_NOUNS)
        assert by_design(name, rng.choice(_ACCESS).format(n=noun)), (name, noun)
        assert not by_design(name, rng.choice(_DATAOP).format(n=noun)), (name, noun)
