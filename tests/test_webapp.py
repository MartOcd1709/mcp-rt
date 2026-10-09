"""Dashboard service: auth gating, org isolation, public proof links (FastAPI TestClient).

No real scan (needs npx); seeds signed attestations in the store and checks the API is token-gated,
scoped per org, and that public share ids serve the attestation without auth.
"""
import json

import pytest

from mcp_rt import attest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient
from hunt import webapp
from hunt.platform_db import Store


def _signed(verdict="CLEAN"):
    key = attest.ed25519.Ed25519PrivateKey.generate()
    rep = {"target": "npx -y demo-mcp", "scanned_at": "2026-10-09T00:00:00", "verdict": verdict,
           "findings": [], "coverage": [{"cls": "sql_injection", "verdict": verdict}]}
    return attest.sign(attest.build_claim(rep, mcp_rt_version="1.0"), key)


def _setup(tmp_path):
    store = Store(f"sqlite:///{tmp_path}/t.db")
    tok = store.create_org("acme")
    org = store.org_for_token(tok)
    env = _signed()
    pid = store.save(org, slug="demo", target="npx -y demo-mcp", verdict="CLEAN", tier="basic",
                     envelope=json.dumps(env), report="{}", badge=attest.make_badge(env), scanned_at="t")
    return TestClient(webapp.create_app(store)), tok, pid, store


def _auth(tok):
    return {"Authorization": "Bearer " + tok}


def test_pages_serve_publicly(tmp_path):
    c, *_ = _setup(tmp_path)
    assert "Attestation Dashboard" in c.get("/").text
    assert "Verify Attestation" in c.get("/verify").text


def test_servers_api_requires_token(tmp_path):
    c, tok, _, _ = _setup(tmp_path)
    assert c.get("/api/servers").status_code == 401            # no token
    assert c.get("/api/servers", headers={"Authorization": "Bearer nope"}).status_code == 401
    d = c.get("/api/servers", headers=_auth(tok)).json()
    assert d["total"] == 1 and d["tiles"]["CLEAN"] == 1 and d["servers"][0]["signed_valid"] is True


def test_org_isolation(tmp_path):
    c, tok_a, _, store = _setup(tmp_path)
    tok_b = store.create_org("other")                          # a second tenant
    assert c.get("/api/servers", headers=_auth(tok_b)).json()["total"] == 0


def test_public_proof_link_needs_no_auth(tmp_path):
    c, _, pid, _ = _setup(tmp_path)
    r = c.get(f"/a/{pid}.json")
    assert r.status_code == 200 and r.json()["sig"]["alg"] == "ed25519"
    assert c.get(f"/a/{pid}.svg").status_code == 200
    assert "Verify Attestation" in c.get(f"/a/{pid}").text     # share page renders
    assert c.get("/a/bogus.json").status_code == 404


def test_scan_requires_token_and_target(tmp_path):
    c, tok, _, _ = _setup(tmp_path)
    assert c.post("/api/scan", json={"target": "x"}).status_code == 401     # no token
    assert c.post("/api/scan", json={"target": ""}, headers=_auth(tok)).status_code == 400


def test_scan_returns_job_scoped_to_org(tmp_path, monkeypatch):
    c, tok, _, _ = _setup(tmp_path)
    monkeypatch.setattr(webapp, "_run_job", lambda *a, **k: None)
    jid = c.post("/api/scan", json={"target": "npx -y x"}, headers=_auth(tok)).json()["job_id"]
    assert c.get(f"/api/jobs/{jid}", headers=_auth(tok)).json()["status"] in ("running", "unknown")
