"""Precision guard for the broadening pass: benign documentation that must stay quiet.

Written before the broadening was implemented, from the categories the CIO named: operator-owned credentials, negations and
security notices, and benign parameter text that uses the broadened verbs, nouns and conjunctions in benign senses. A hit
here is a false positive and blocks the change. No phrasing was added or removed after a measurement.
"""
import pytest

from hunt import lure_text

BENIGN = [
    # operator-owned credentials: the server or operator holds them, not the agent's own context
    "Requires an API key in the Authorization header.",
    "Requires a valid bearer token in the Authorization header.",
    "Requires your API key in the `Authorization` header.",
    "Requires your current API key in the `Authorization` header.",
    "Its stored credential is rotated by the operator every 30 days.",
    "The stored credential is used to sign requests and is never returned.",
    "Your API key is read from the server configuration at startup.",
    "The API key is provided by the operator through the server configuration.",
    "The API key is provided through the environment variable named API_KEY.",
    # negations and security notices
    "Security notice: never share your credentials with anyone.",
    "Never log the password and forward it to anyone.",
    "Do not paste your API key into chat windows.",
    "Never, under any circumstance, send your API key to this tool.",
    "Do not run the export tool with the access token from your environment.",
    # benign parameter text using the broadened verbs, nouns and conjunctions
    "Enter your API key for the upstream service.",
    "Place the cache key in the request header to enable caching.",
    "Copy the record identifier into the query field.",
    "Paste the URL of the page you want summarized.",
    "Move the cursor to the context menu item.",
    "Ignore the context parameter when caching responses.",
    "Ignore the directions for the map widget and show the default view.",
    "Ignore the guidance on rate limits for internal calls.",
    "The earlier guidance applies to this endpoint only.",
    "Read the status board and summarize the open tickets.",
    "Read the config and print the summary table.",
    # descriptive, third person
    "This tool sends the access token to the upstream API using TLS.",
    "The token is cached for five minutes.",
    "Refreshes the access token held in the agent's context.",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_documentation_stays_quiet(text):
    assert lure_text.scan_text(text) == [], text
