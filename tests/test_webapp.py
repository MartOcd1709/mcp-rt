"""Dashboard service smoke tests (FastAPI TestClient) — read paths + input validation.

Does not run a real scan (that needs npx/strace); it seeds a signed attestation and checks the
dashboard surfaces it with ground-truth verdict tiles, serves the data files, and rejects a
scan request with no target.
"""
import json

import pytest

from mcp_rt import attest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient
from hunt import webapp


def _seed(data_dir):
    key = attest.ed25519.Ed25519PrivateKey.generate()
    rep = {"target": "npx -y demo-mcp", "scanned_at": "2026-10-09T00:00:00", "verdict": "CLEAN",
           "findings": [], "coverage": [{"cls": "sql_injection", "verdict": "CLEAN"}]}
    env = attest.sign(attest.build_claim(rep, mcp_rt_version="1.0"), key)
    (data_dir / "demo-mcp.attestation.json").write_text(json.dumps(env), encoding="utf-8")
    (data_dir / "demo-mcp.badge.svg").write_text(attest.make_badge(env), encoding="utf-8")


def _client(tmp_path):
    _seed(tmp_path)
    return TestClient(webapp.create_app(tmp_path))


def test_dashboard_and_verify_pages_serve(tmp_path):
    c = _client(tmp_path)
    assert "Attestation Dashboard" in c.get("/").text
    assert "Verify Attestation" in c.get("/verify").text


def test_servers_api_reports_ground_truth_tiles(tmp_path):
    d = _client(tmp_path).get("/api/servers").json()
    assert d["total"] == 1 and d["tiles"]["CLEAN"] == 1
    row = d["servers"][0]
    assert row["verdict"] == "CLEAN" and row["signed_valid"] is True


def test_data_files_served_and_path_escape_blocked(tmp_path):
    c = _client(tmp_path)
    assert c.get("/data/demo-mcp.badge.svg").status_code == 200
    assert c.get("/data/demo-mcp.attestation.json").status_code == 200
    assert c.get("/data/..%2f..%2fetc%2fpasswd").status_code == 404   # no traversal


def test_scan_requires_target(tmp_path):
    assert _client(tmp_path).post("/api/scan", json={"target": ""}).status_code == 400


def test_scan_returns_job_id(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "_run_job", lambda *a, **k: None)   # don't run a real scan
    r = _client(tmp_path).post("/api/scan", json={"target": "npx -y x"})
    assert r.status_code == 200 and "job_id" in r.json()
