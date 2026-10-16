"""SSO (OIDC): config gating, first-login user provisioning, and the /api/me identity probe.

The full OAuth round-trip needs a live identity provider (client id/secret), so here we test the
parts that don't: config is off unless env is set, a first-time SSO user is auto-provisioned with
the default role (then reused), and the dashboard can tell whether anyone is signed in.
"""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("authlib")
from fastapi.testclient import TestClient
from hunt import sso, webapp
from hunt.platform_db import Store


def test_sso_disabled_without_env(monkeypatch):
    for k in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    assert sso.sso_config() is None
    assert sso.configure_sso(object(), object()) is False      # no routes wired


def test_sso_config_parsed_with_env(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://accounts.example.com/")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "sec")
    monkeypatch.setenv("OIDC_ORG_ID", "7")
    cfg = sso.sso_config()
    assert cfg["issuer"] == "https://accounts.example.com" and cfg["org_id"] == 7
    assert cfg["default_role"] == "member"


def test_provision_creates_then_reuses(tmp_path):
    s = Store(f"sqlite:///{tmp_path}/t.db")
    org = s.org_for_token(s.create_org("acme"))
    assert sso.provision_sso_user(s, org, "alice@acme.com", "member") == "member"   # created
    s.set_role(org, "alice@acme.com", "admin")
    assert sso.provision_sso_user(s, org, "alice@acme.com", "member") == "admin"     # reused, keeps role


def test_me_reports_unauthenticated_and_sso_off(tmp_path, monkeypatch):
    for k in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    c = TestClient(webapp.create_app(Store(f"sqlite:///{tmp_path}/t.db")))
    d = c.get("/api/me").json()
    assert d["authenticated"] is False and d["sso_enabled"] is False
