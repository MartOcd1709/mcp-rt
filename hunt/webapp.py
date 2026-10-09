"""`mcp-rt serve` — the multi-tenant scan service + dashboard (localhost now, same code on a VPS).

A FastAPI app over the engine. Enterprise shape:
  * **Private management API** — `/api/*` requires a Bearer API token and is scoped to that org,
    so one deployment serves many tenants with no cross-tenant leakage.
  * **Public proof links** — `/a/{public_id}` share an attestation by an unguessable id (an
    attestation is signed proof meant to be shared and verified; listing/scanning is private).
  * **Durable store** — hunt.platform_db (SQLAlchemy): SQLite locally, Postgres on the VPS via
    DATABASE_URL, no code change.

Every verdict is GROUND TRUTH (the attack fired or it didn't, zero false positives) and every
row carries a signed, offline-verifiable attestation no competitor's dashboard produces.

    mcp-rt serve                       # http://127.0.0.1:8900 ; prints a dev API token
    DATABASE_URL=postgresql+psycopg://… mcp-rt serve --host 0.0.0.0   # VPS
"""
from __future__ import annotations

import argparse
import json
import threading
import uuid
from pathlib import Path

from mcp_rt import attest
from hunt.platform_db import ROLES, Store, role_ok

_JOBS: dict[str, dict] = {}


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("mcp-rt")
    except Exception:  # noqa: BLE001
        return "0+unknown"


def _slug(target: str) -> str:
    import re
    return (re.sub(r"[^a-zA-Z0-9]+", "-", target).strip("-").lower() or "target")[:60]


def _run_job(store: Store, job_id: str, org_id: int, target: str, tier: str, agent: bool) -> None:
    """Background worker: scan -> sign -> persist to the org. Updates _JOBS in place."""
    import shlex
    import asyncio
    from hunt.report import run_full_scan
    from hunt.check import deep_scan
    try:
        if tier == "deep":
            ds = deep_scan(target, do_cap=True, do_agent=agent)
            report = ds["base"] or {}
            claim = attest.build_claim(report, capture="direct-probe", mcp_rt_version=_version(),
                                       tier="deep", deep=ds)
            evidence = attest.evidence_object(report, ds)
        else:
            report = asyncio.run(run_full_scan(shlex.split(target)))
            claim = attest.build_claim(report, capture="direct-probe", mcp_rt_version=_version())
            evidence = attest.evidence_object(report)
        env = attest.sign(claim, attest.load_or_create_key())
        public_id, change = store.save(org_id, slug=_slug(target), target=target,
                                       verdict=claim["scan"]["verdict"], tier=tier,
                                       envelope=json.dumps(env), report=json.dumps(evidence),
                                       badge=attest.make_badge(env), scanned_at=claim.get("scanned_at", ""))
        _JOBS[job_id] = {"status": "done", "org_id": org_id, "target": target,
                         "verdict": claim["scan"]["verdict"], "tier": tier,
                         "public_id": public_id, "change": change}
    except Exception as exc:  # noqa: BLE001 — surface to the dashboard, never crash the server
        _JOBS[job_id] = {"status": "error", "org_id": org_id, "target": target, "error": str(exc)[:300]}


def create_app(store: Store):
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    app = FastAPI(title="mcp-rt", docs_url="/api/docs")
    here = Path(__file__).parent

    def auth(authorization: str | None, minimum: str = "viewer") -> int:
        """Resolve the Bearer token to an org and enforce the minimum role (RBAC)."""
        token = authorization.split(" ", 1)[1] if authorization and " " in authorization else (authorization or "")
        org_id, role = store.token_role(token.strip())
        if org_id is None:
            raise HTTPException(status_code=401, detail="invalid or missing API token")
        if not role_ok(role, minimum):
            raise HTTPException(status_code=403, detail=f"requires '{minimum}' role (token is '{role}')")
        return org_id

    def require_org(authorization: str | None = Header(None)) -> int:   # viewer+ (read)
        return auth(authorization, "viewer")

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return (here / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/verify", response_class=HTMLResponse)
    def verify_page():
        return (here / "verify.html").read_text(encoding="utf-8")

    # ---- private management API (Bearer token, org-scoped) --------------------------------
    @app.post("/api/scan")
    def start_scan(body: dict, authorization: str | None = Header(None)):
        org_id = auth(authorization, "member")          # scanning is a write -> member+
        target = (body or {}).get("target", "").strip()
        if not target:
            return JSONResponse({"error": "target required"}, status_code=400)
        tier = "deep" if (body or {}).get("deep") else "basic"
        agent = bool((body or {}).get("agent_redteam"))
        job_id = uuid.uuid4().hex[:12]
        _JOBS[job_id] = {"status": "running", "org_id": org_id, "target": target, "tier": tier}
        threading.Thread(target=_run_job, args=(store, job_id, org_id, target, tier, agent),
                         daemon=True).start()
        return {"job_id": job_id}

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str, authorization: str | None = Header(None)):
        org_id = require_org(authorization)
        j = _JOBS.get(job_id)
        if not j or j.get("org_id") != org_id:        # never reveal another org's job
            return {"status": "unknown"}
        return j

    @app.get("/api/servers")
    def servers(authorization: str | None = Header(None)):
        org_id = require_org(authorization)
        rows, tiles = [], {"CLEAN": 0, "VULNERABLE": 0, "INCONCLUSIVE": 0}
        regressed = 0
        for a in store.list(org_id):
            env = json.loads(a.envelope)
            ok, _ = attest.verify(env)
            s = env.get("claim", {}).get("scan", {})
            tiles[a.verdict] = tiles.get(a.verdict, 0) + 1
            if a.change == "regressed":
                regressed += 1
            rows.append({"public_id": a.public_id, "target": a.target, "verdict": a.verdict,
                         "tier": a.tier, "change": a.change, "classes": s.get("classes_tested", []),
                         "components": s.get("components", {}),
                         "findings": env.get("claim", {}).get("finding_summary", {}),
                         "scanned": a.scanned_at, "signed_valid": ok})
        changes = [{"target": r.slug, "verdict": r.verdict, "change": r.change, "scanned": r.scanned_at}
                   for r in store.recent_changes(org_id)]
        return {"servers": rows, "tiles": tiles, "total": len(rows),
                "regressed": regressed, "changes": changes}

    @app.post("/api/rescan/{public_id}")
    def rescan(public_id: str, authorization: str | None = Header(None)):
        org_id = auth(authorization, "member")          # rescan is a write -> member+
        a = store.get_public(public_id)
        if not a or a.org_id != org_id:
            return JSONResponse({"error": "not found"}, status_code=404)
        job_id = uuid.uuid4().hex[:12]
        _JOBS[job_id] = {"status": "running", "org_id": org_id, "target": a.target, "tier": a.tier}
        threading.Thread(target=_run_job, args=(store, job_id, org_id, a.target, a.tier, False),
                         daemon=True).start()
        return {"job_id": job_id}

    @app.get("/api/history/{public_id}")
    def history(public_id: str, authorization: str | None = Header(None)):
        org_id = require_org(authorization)
        a = store.get_public(public_id)
        if not a or a.org_id != org_id:        # org-scoped even though lookup is by public id
            return {"history": []}
        return {"history": [{"verdict": r.verdict, "tier": r.tier, "change": r.change,
                             "scanned": r.scanned_at} for r in store.history(org_id, a.slug)]}

    # ---- org/user admin + token minting (admin+) ------------------------------------------
    @app.get("/api/users")
    def list_users(authorization: str | None = Header(None)):
        org_id = auth(authorization, "admin")
        return {"users": [{"email": u.email, "role": u.role} for u in store.list_users(org_id)],
                "roles": list(ROLES)}

    @app.post("/api/users")
    def add_user(body: dict, authorization: str | None = Header(None)):
        org_id = auth(authorization, "admin")
        email = (body or {}).get("email", "").strip()
        role = (body or {}).get("role", "member")
        if not email:
            return JSONResponse({"error": "email required"}, status_code=400)
        if role not in ROLES:
            return JSONResponse({"error": f"role must be one of {list(ROLES)}"}, status_code=400)
        store.add_user(org_id, email, role)
        return {"ok": True, "email": email, "role": role}

    @app.post("/api/users/role")
    def set_role(body: dict, authorization: str | None = Header(None)):
        org_id = auth(authorization, "admin")
        ok = store.set_role(org_id, (body or {}).get("email", ""), (body or {}).get("role", ""))
        return JSONResponse({"ok": ok}, status_code=200 if ok else 400)

    @app.post("/api/tokens")
    def mint_token(body: dict, authorization: str | None = Header(None)):
        org_id = auth(authorization, "admin")
        role = (body or {}).get("role", "member")
        if role not in ROLES:
            return JSONResponse({"error": f"role must be one of {list(ROLES)}"}, status_code=400)
        return {"token": store.create_token(org_id, role), "role": role}   # shown once

    # ---- public proof links (unguessable id; an attestation is meant to be shared) ---------
    # Suffix routes are declared BEFORE the catch-all page route so ".json"/".svg" aren't
    # swallowed by the {public_id} path param (which otherwise matches dots).
    @app.get("/a/{public_id}.json")
    def share_json(public_id: str):
        a = store.get_public(public_id)
        if not a:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(json.loads(a.envelope))

    @app.get("/a/{public_id}.svg")
    def share_badge(public_id: str):
        a = store.get_public(public_id)
        if not a:
            return Response("not found", status_code=404)
        return Response(a.badge, media_type="image/svg+xml")

    @app.get("/a/{public_id}", response_class=HTMLResponse)
    def share_page(public_id: str):
        # the verify page auto-loads ?att=<json url>; point it at the public json endpoint
        return (here / "verify.html").read_text(encoding="utf-8").replace(
            "</head>", f"<script>location.search||history.replaceState(0,'', '?att=/a/{public_id}.json')</script></head>", 1)

    return app


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt serve",
                                description="Run the mcp-rt scan service + dashboard (localhost or VPS).")
    p.add_argument("--port", type=int, default=8900)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--db", default=None, help="DB url (default: $DATABASE_URL or sqlite:///mcprt_platform.db)")
    p.add_argument("--monitor-interval", type=int, default=0, metavar="SEC",
                   help="continuous monitoring: rescan every tracked server every SEC seconds "
                        "(0 = off). Rescans surface rug-pull/drift automatically.")
    args = p.parse_args(argv)
    import uvicorn
    store = Store(args.db)
    token = store.ensure_default_org()
    app = create_app(store)
    if args.monitor_interval > 0:
        _start_monitor(store, args.monitor_interval)
        print(f"continuous monitoring ON — rescanning every {args.monitor_interval}s", flush=True)
    print(f"mcp-rt dashboard → http://{args.host}:{args.port}", flush=True)
    print(f"dev API token (paste into the dashboard login):\n    {token}\n", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def _start_monitor(store: Store, interval: int) -> None:
    """Background scheduler: periodically rescan every tracked server so drift surfaces on its own."""
    import time

    def _loop():
        while True:
            time.sleep(interval)
            for org_id, _slug, target, tier in store.all_targets():
                jid = uuid.uuid4().hex[:12]
                _JOBS[jid] = {"status": "running", "org_id": org_id, "target": target, "tier": tier}
                _run_job(store, jid, org_id, target, tier, False)   # serial: don't hammer npx/strace
    threading.Thread(target=_loop, daemon=True).start()


if __name__ == "__main__":
    import sys
    sys.exit(main())
