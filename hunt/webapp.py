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
# NOTE: deliberately NOT using `from __future__ import annotations` — FastAPI resolves route
# param annotations via module globals, and `Request` is imported inside create_app(), so lazy
# string annotations would make FastAPI mis-read `request` as a query param (422). Eager wins here.
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
    import os
    from hunt.report import run_full_scan
    from hunt.check import deep_scan
    backend = os.getenv("MCPRT_SCAN_BACKEND", "inproc")   # inproc | subprocess | docker | auto
    try:
        if tier == "deep":
            # deep tier runs the MCP-00 strace hunt in-process (harder to containerise); isolate later.
            ds = deep_scan(target, do_cap=True, do_agent=agent)
            report = ds["base"] or {}
            claim = attest.build_claim(report, capture="direct-probe", mcp_rt_version=_version(),
                                       tier="deep", deep=ds)
            evidence = attest.evidence_object(report, ds)
        else:
            if backend in ("subprocess", "docker", "auto"):
                from hunt.sandbox import run_isolated      # fresh env/container per scan -> reliable at scale
                report = run_isolated(target, backend=backend)
            else:
                report = asyncio.run(run_full_scan(shlex.split(target)))
            claim = attest.build_claim(report, capture=f"direct-probe/{backend}", mcp_rt_version=_version())
            evidence = attest.evidence_object(report)
        env = attest.sign(claim, attest.load_or_create_key())
        verdict = claim["scan"]["verdict"]
        public_id, change = store.save(org_id, slug=_slug(target), target=target,
                                       verdict=verdict, tier=tier,
                                       envelope=json.dumps(env), report=json.dumps(evidence),
                                       badge=attest.make_badge(env), scanned_at=claim.get("scanned_at", ""))
        if change == "regressed":      # CLEAN -> VULNERABLE: alert the org's channels (best-effort)
            import os
            from hunt.notify import notify_regression
            base = os.getenv("MCPRT_PUBLIC_URL", "").rstrip("/")
            proof_url = f"{base}/a/{public_id}" if base else f"/a/{public_id}"
            notify_regression(store, org_id, target, "CLEAN", verdict, proof_url,
                              claim.get("finding_summary", {}))
        _JOBS[job_id] = {"status": "done", "org_id": org_id, "target": target,
                         "verdict": verdict, "tier": tier,
                         "public_id": public_id, "change": change}
    except Exception as exc:  # noqa: BLE001 — surface to the dashboard, never crash the server
        _JOBS[job_id] = {"status": "error", "org_id": org_id, "target": target, "error": str(exc)[:300]}


def create_app(store: Store):
    import os
    import secrets as _secrets
    from fastapi import FastAPI, Header, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    from starlette.middleware.sessions import SessionMiddleware
    from hunt.sso import configure_sso, sso_config
    app = FastAPI(title="mcp-rt", docs_url="/api/docs")
    # Signed-cookie sessions (for SSO logins). Set SESSION_SECRET in prod so sessions survive restarts.
    app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET") or _secrets.token_urlsafe(32))
    sso_enabled = configure_sso(app, store)
    here = Path(__file__).parent

    def _identity(request: Request, authorization: str | None) -> tuple[int | None, str | None]:
        """Who is calling: an SSO session (browser login) OR a Bearer API token. Session wins."""
        sess = getattr(request, "session", {}) or {}
        if sess.get("org_id") is not None:
            return sess["org_id"], sess.get("role", "viewer")
        token = authorization.split(" ", 1)[1] if authorization and " " in authorization else (authorization or "")
        return store.token_role(token.strip())

    def auth(request: Request, authorization: str | None, minimum: str = "viewer") -> int:
        """Resolve the caller (session or token) and enforce the minimum role (RBAC)."""
        org_id, role = _identity(request, authorization)
        if org_id is None:
            raise HTTPException(status_code=401, detail="sign in (SSO) or send a valid API token")
        if not role_ok(role, minimum):
            raise HTTPException(status_code=403, detail=f"requires '{minimum}' role (you are '{role}')")
        return org_id

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return (here / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/verify", response_class=HTMLResponse)
    def verify_page():
        return (here / "verify.html").read_text(encoding="utf-8")

    # ---- private management API (Bearer token, org-scoped) --------------------------------
    @app.post("/api/scan")
    def start_scan(body: dict, request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization, "member")          # scanning is a write -> member+
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
    def job_status(job_id: str, request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization)
        j = _JOBS.get(job_id)
        if not j or j.get("org_id") != org_id:        # never reveal another org's job
            return {"status": "unknown"}
        return j

    @app.get("/api/servers")
    def servers(request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization)
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
    def rescan(public_id: str, request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization, "member")          # rescan is a write -> member+
        a = store.get_public(public_id)
        if not a or a.org_id != org_id:
            return JSONResponse({"error": "not found"}, status_code=404)
        job_id = uuid.uuid4().hex[:12]
        _JOBS[job_id] = {"status": "running", "org_id": org_id, "target": a.target, "tier": a.tier}
        threading.Thread(target=_run_job, args=(store, job_id, org_id, a.target, a.tier, False),
                         daemon=True).start()
        return {"job_id": job_id}

    @app.get("/api/history/{public_id}")
    def history(public_id: str, request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization)
        a = store.get_public(public_id)
        if not a or a.org_id != org_id:        # org-scoped even though lookup is by public id
            return {"history": []}
        return {"history": [{"verdict": r.verdict, "tier": r.tier, "change": r.change,
                             "scanned": r.scanned_at} for r in store.history(org_id, a.slug)]}

    # ---- org/user admin + token minting (admin+) ------------------------------------------
    @app.get("/api/users")
    def list_users(request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization, "admin")
        return {"users": [{"email": u.email, "role": u.role} for u in store.list_users(org_id)],
                "roles": list(ROLES)}

    @app.post("/api/users")
    def add_user(body: dict, request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization, "admin")
        email = (body or {}).get("email", "").strip()
        role = (body or {}).get("role", "member")
        if not email:
            return JSONResponse({"error": "email required"}, status_code=400)
        if role not in ROLES:
            return JSONResponse({"error": f"role must be one of {list(ROLES)}"}, status_code=400)
        store.add_user(org_id, email, role)
        return {"ok": True, "email": email, "role": role}

    @app.post("/api/users/role")
    def set_role(body: dict, request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization, "admin")
        ok = store.set_role(org_id, (body or {}).get("email", ""), (body or {}).get("role", ""))
        return JSONResponse({"ok": ok}, status_code=200 if ok else 400)

    @app.post("/api/tokens")
    def mint_token(body: dict, request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization, "admin")
        role = (body or {}).get("role", "member")
        if role not in ROLES:
            return JSONResponse({"error": f"role must be one of {list(ROLES)}"}, status_code=400)
        return {"token": store.create_token(org_id, role), "role": role}   # shown once

    @app.get("/api/integrations")
    def list_integrations(request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization, "admin")
        return {"configured": store.list_integration_kinds(org_id)}   # kinds only, never the secrets

    @app.post("/api/integrations/{kind}")
    def set_integration(kind: str, body: dict, request: Request, authorization: str | None = Header(None)):
        org_id = auth(request, authorization, "admin")
        if kind not in ("slack", "jira"):
            return JSONResponse({"error": "kind must be 'slack' or 'jira'"}, status_code=400)
        if not isinstance(body, dict) or not body:
            return JSONResponse({"error": "config required"}, status_code=400)
        store.set_integration(org_id, kind, body)
        return {"ok": True, "kind": kind}

    @app.get("/api/me")
    def me(request: Request, authorization: str | None = Header(None)):
        org_id, role = _identity(request, authorization)
        sess = getattr(request, "session", {}) or {}
        return {"authenticated": org_id is not None, "org_id": org_id, "role": role,
                "email": sess.get("email"), "sso_enabled": sso_enabled}

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
    p.add_argument("--scan-backend", choices=["inproc", "subprocess", "docker", "auto"],
                   default="subprocess",
                   help="per-scan isolation: subprocess (default, fresh env per scan, no Docker) | "
                        "docker (fresh container per scan, VPS/production) | auto | inproc (no isolation)")
    args = p.parse_args(argv)
    import os as _os
    _os.environ["MCPRT_SCAN_BACKEND"] = args.scan_backend   # read by _run_job + hunt.sandbox
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
