"""No-auth interpretation: a credential-free session is a VULN only when auth was supplied."""
from hunt.remote import _auth_headers, _unauth_finding


def test_auth_header_detection():
    assert _auth_headers({"Authorization": "Bearer x"})
    assert _auth_headers({"X-API-Key": "k"})
    assert _auth_headers({"Cookie": "s=1"})
    assert not _auth_headers({"X-Tenant-Id": "acme"})   # routing header, not auth
    assert not _auth_headers({})


def test_unauth_finding_matrix():
    assert _unauth_finding(True, True)["cls"] == "missing_auth"   # supplied, not enforced -> finding
    assert _unauth_finding(True, False) is None                   # supplied, enforced -> clean
    assert _unauth_finding(False, True) is None                   # open server -> never a finding
    assert _unauth_finding(False, False) is None
