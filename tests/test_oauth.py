"""OAuth AS-metadata posture: PKCE + confirmed open-DCR evaluation (pure, no network)."""
from hunt.remote import _oauth_findings


def _cls(findings):
    return {f["cls"] for f in findings}


def test_strong_oauth_is_clean():
    meta = {"code_challenge_methods_supported": ["S256"], "registration_endpoint": "https://as/reg"}
    assert _oauth_findings(meta, dcr_open=False) == []       # PKCE S256 + DCR protected -> clean


def test_missing_pkce_flagged():
    assert _cls(_oauth_findings({"code_challenge_methods_supported": ["plain"]}, None)) == {"oauth_pkce"}
    assert _cls(_oauth_findings({}, None)) == {"oauth_pkce"}  # absent entirely


def test_confirmed_open_dcr_flagged():
    meta = {"code_challenge_methods_supported": ["S256"], "registration_endpoint": "https://as/reg"}
    assert _cls(_oauth_findings(meta, dcr_open=True)) == {"oauth_open_dcr"}
    # dcr_open None (couldn't confirm) must NOT flag — we never report an unconfirmed weakness
    assert _oauth_findings(meta, dcr_open=None) == []


def test_both_weak():
    meta = {"code_challenge_methods_supported": [], "registration_endpoint": "https://as/reg"}
    assert _cls(_oauth_findings(meta, dcr_open=True)) == {"oauth_pkce", "oauth_open_dcr"}
