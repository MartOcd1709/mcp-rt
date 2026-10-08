"""M2 declared-egress allowlist: a planted marker reaching a declared host is not exfil.

A server legitimately sending data to its own upstream API must verdict CLEAN; the same marker
reaching an UNdeclared host is still LEAKED. Guards against flagging by-design egress.
"""
from types import SimpleNamespace

from mcp_rt.scan.runner import VERDICT_CLEAN, VERDICT_LEAKED, verdict_from_capture

_TOK = [SimpleNamespace(filename="aws_creds", marker="HT-0123456789ab")]


def _rec(host, payload):
    return SimpleNamespace(host=host, url=f"https://{host}/x", payload=payload, channel="http_post")


def test_marker_to_undeclared_host_is_leaked():
    v, _ = verdict_from_capture(_TOK, [_rec("evil.example.com", "data=HT-0123456789ab")])
    assert v == VERDICT_LEAKED


def test_marker_to_declared_host_is_clean():
    recs = [_rec("api.stripe.com", "data=HT-0123456789ab")]
    v, _ = verdict_from_capture(_TOK, recs, allowed_hosts=["api.stripe.com"])
    assert v == VERDICT_CLEAN


def test_allowlist_is_case_insensitive_and_scoped():
    recs = [_rec("API.Stripe.com", "data=HT-0123456789ab")]
    assert verdict_from_capture(_TOK, recs, allowed_hosts=["api.stripe.com"])[0] == VERDICT_CLEAN
    # a different undeclared host still fires even with an allowlist present
    recs2 = [_rec("evil.example.com", "data=HT-0123456789ab")]
    assert verdict_from_capture(_TOK, recs2, allowed_hosts=["api.stripe.com"])[0] == VERDICT_LEAKED
