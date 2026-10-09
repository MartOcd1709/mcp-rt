"""Regression notifications — alert the team where they work when a server rug-pulls.

Closes the monitoring loop (detect drift -> alert humans -> track the fix). Fires only on a
CLEAN->VULNERABLE transition (the `regressed` event the scan already computes), so repeat scans
never spam. Each org configures its own channels (Slack webhook / Jira), stored per-org.

Delivery is best-effort: a failing/unreachable channel is logged and swallowed — a notification
problem must never fail a scan.
"""
from __future__ import annotations


def _post(url: str, *, json=None, auth=None, headers=None, timeout=8) -> bool:
    try:
        import httpx
        r = httpx.post(url, json=json, auth=auth, headers=headers, timeout=timeout)
        return r.status_code < 300
    except Exception:  # noqa: BLE001 — never let a notification failure break a scan
        return False


def send_slack(webhook_url: str, server: str, old: str, new: str, proof_url: str, findings: dict) -> bool:
    fset = ", ".join(f"{k}: {v}" for k, v in (findings or {}).items()) or "see report"
    text = (f":rotating_light: *mcp-rt regression* — `{server}` went *{old} → {new}*.\n"
            f"Findings: {fset}\nSigned proof: {proof_url}")
    return _post(webhook_url, json={"text": text})


def send_jira(cfg: dict, server: str, old: str, new: str, proof_url: str, findings: dict) -> bool:
    url = cfg.get("url", "").rstrip("/")
    email, token, project = cfg.get("email"), cfg.get("token"), cfg.get("project")
    if not (url and email and token and project):
        return False
    fset = ", ".join(f"{k}: {v}" for k, v in (findings or {}).items()) or "see report"
    issue = {"fields": {
        "project": {"key": project},
        "issuetype": {"name": cfg.get("issuetype", "Bug")},
        "summary": f"mcp-rt: MCP server '{server}' regressed ({old} → {new})",
        "description": (f"mcp-rt ground-truth scan regressed '{server}' from {old} to {new}.\n"
                        f"Findings: {fset}\nSigned, verifiable proof: {proof_url}"),
    }}
    return _post(f"{url}/rest/api/3/issue", json=issue, auth=(email, token),
                 headers={"Accept": "application/json"})


def notify_regression(store, org_id: int, server: str, old: str, new: str,
                      proof_url: str, findings: dict) -> list[str]:
    """Fire every channel the org has configured. Returns the kinds that were attempted."""
    fired = []
    slack = store.get_integration(org_id, "slack")
    if slack and slack.get("webhook_url"):
        send_slack(slack["webhook_url"], server, old, new, proof_url, findings)
        fired.append("slack")
    jira = store.get_integration(org_id, "jira")
    if jira:
        send_jira(jira, server, old, new, proof_url, findings)
        fired.append("jira")
    return fired
