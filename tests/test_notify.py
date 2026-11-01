"""Regression notifications: payload shape, config gating, and per-org channel fan-out (mocked).

No real Slack/Jira calls — _post / send_* are monkeypatched. Verifies a regression builds the
right message, Jira needs full creds, and only configured channels fire.
"""
import hunt.notify as notify
from hunt.platform_db import Store


def test_slack_builds_and_posts(monkeypatch):
    calls = []
    monkeypatch.setattr(notify, "_post", lambda url, **k: calls.append((url, k)) or True)
    notify.send_slack("https://hooks.slack/x", "srv", "CLEAN", "VULNERABLE", "/a/abc", {"Critical": 1})
    assert calls and calls[0][0] == "https://hooks.slack/x"
    text = calls[0][1]["json"]["text"]
    assert "srv" in text and "CLEAN" in text and "VULNERABLE" in text and "/a/abc" in text


def test_jira_needs_full_config(monkeypatch):
    posted = []
    monkeypatch.setattr(notify, "_post", lambda url, **k: posted.append(url) or True)
    full = {"url": "https://acme.atlassian.net", "email": "e@acme.com", "token": "t", "project": "SEC"}
    assert notify.send_jira(full, "srv", "CLEAN", "VULNERABLE", "/a/x", {}) is True
    assert posted[0].endswith("/rest/api/3/issue")
    assert notify.send_jira({"url": "https://j"}, "srv", "CLEAN", "VULNERABLE", "/a/x", {}) is False  # no creds


def test_notify_regression_fires_only_configured(tmp_path, monkeypatch):
    s = Store(f"sqlite:///{tmp_path}/t.db")
    org = s.org_for_token(s.create_org("acme"))
    sent = []
    monkeypatch.setattr(notify, "send_slack", lambda *a, **k: sent.append("slack") or True)
    monkeypatch.setattr(notify, "send_jira", lambda *a, **k: sent.append("jira") or True)
    assert notify.notify_regression(s, org, "srv", "CLEAN", "VULNERABLE", "/a/x", {}) == []   # none configured
    s.set_integration(org, "slack", {"webhook_url": "https://hooks/x"})
    assert notify.notify_regression(s, org, "srv", "CLEAN", "VULNERABLE", "/a/x", {}) == ["slack"]
    assert sent == ["slack"]


def test_delivery_failure_is_swallowed(monkeypatch):
    # A broken channel must not raise — a notification problem can't fail a scan.
    def _boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr("httpx.post", _boom)
    assert notify.send_slack("https://hooks/x", "s", "CLEAN", "VULNERABLE", "/a/x", {}) is False
