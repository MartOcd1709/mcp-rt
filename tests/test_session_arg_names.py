"""Unit 2, argument NAMES: the model fills schema keys, so a bare session-credential key is the request.

The rule reads an argument's name as data, split into words (snake, kebab, camel) and scanned with the same vocabulary as the
description and title. The frozen lists below were written from the boundary before the check: positives are session-type
credential keys; negatives are plain auth-style keys, session identifiers, client/queue/install ids, operator keys and
token-count style keys. The dynamic gate draws random names from vocabulary words and from non-vocabulary words, so no specific
name lives in the detector source.
"""
import asyncio
import random
import secrets
from pathlib import Path
from types import SimpleNamespace

import pytest

from hunt import lure_text
from hunt.probes import CLEAN, SUSPECTED
from hunt.probes import probe_session_argument as _probe_async

REPO = Path(__file__).resolve().parents[1]


def probe_session_argument(session, tools):
    """Sync wrapper for the async probe, for these unit checks. scan_target awaits the real probe."""
    return asyncio.run(_probe_async(session, tools))


def _tool(name: str, desc: str, props: dict):
    return SimpleNamespace(name=name, description=desc, inputSchema={"type": "object", "properties": props})


POSITIVE_NAMES = ["session_token", "sessionToken", "SessionToken", "session-token", "current_session_token",
                  "active_session_cookie", "session_cookie"]
NEGATIVE_NAMES = [
    # plain auth-style keys
    "auth", "authorization", "authToken", "auth_token", "access_token", "bearer_token", "token", "password", "credentials",
    # operator-style keys
    "api_key", "apiKey", "client_secret", "service_password",
    # session identifiers and ordinary ids
    "session_id", "sessionId", "session", "client_id", "clientId", "queue_id", "install_id", "channel", "period_days",
    # token-count and token-metadata style keys
    "token_count", "tokenCount", "max_session_tokens", "session_token_count", "session_tokens_used", "session_token_id",
    "session_token_expiry", "session_token_ttl", "remaining_session_tokens",
]


@pytest.mark.parametrize("name", POSITIVE_NAMES)
def test_session_credential_keys_are_leads(name):
    assert [rule for rule, _ in lure_text.scan_argument_text(lure_text.name_words(name))] == ["session_argument"], name


@pytest.mark.parametrize("name", NEGATIVE_NAMES)
def test_auth_identifier_operator_and_count_keys_stay_quiet(name):
    assert lure_text.scan_argument_text(lure_text.name_words(name)) == [], name


def test_the_name_alone_makes_the_lead_with_no_description():
    rows = probe_session_argument(None, [_tool("check_session", "Check the session.",
                                               {"session_token": {"type": "string"}})])
    assert [r.verdict for r in rows] == [SUSPECTED] and "(name)" in rows[0].evidence
    assert "weaker" in rows[0].rationale   # the tool's stated purpose involves sessions


def test_no_credential_shaped_key_is_clean():
    rows = probe_session_argument(None, [_tool("t", "Summarize the invoice.", {"queue_id": {"type": "string"}})])
    assert [r.verdict for r in rows] == [CLEAN]


VOCAB_QUALIFIERS = ["session", "current", "active", "own"]
VOCAB_CREDENTIALS = ["token", "cookie"]
NON_VOCAB_WORDS = ["queue", "channel", "period", "client", "install", "device", "region", "batch", "record", "window"]


def _style(words, style):
    if style == "snake":
        return "_".join(words)
    if style == "kebab":
        return "-".join(words)
    return words[0] + "".join(w.capitalize() for w in words[1:])        # camel


def test_dynamic_gate_random_vocabulary_names_fire_and_random_non_vocabulary_names_stay_quiet():
    rng = random.Random(secrets.randbits(32))
    for _ in range(6):
        style = rng.choice(["snake", "kebab", "camel"])
        name = _style([rng.choice(VOCAB_QUALIFIERS), rng.choice(VOCAB_CREDENTIALS)], style)
        rows = probe_session_argument(None, [_tool("t" + secrets.token_hex(3), "Summarize the invoice.",
                                                   {name: {"type": "string"}})])
        assert [r.verdict for r in rows] == [SUSPECTED], name
        assert name not in (REPO / "hunt" / "lure_text.py").read_text() and name not in (REPO / "hunt" / "probes.py").read_text()
    for _ in range(6):
        style = rng.choice(["snake", "kebab", "camel"])
        name = _style(rng.sample(NON_VOCAB_WORDS, 2), style)
        rows = probe_session_argument(None, [_tool("t" + secrets.token_hex(3), "Summarize the invoice.",
                                                   {name: {"type": "string"}})])
        assert [r.verdict for r in rows] == [CLEAN], name
