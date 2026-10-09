"""`mcp-rt serve` — the hosted scan service + dashboard (localhost now, same code on a VPS).

A thin FastAPI app over the existing engine: submit a target, it scans (basic or deep) in a
background thread, signs an attestation, and the dashboard shows a Wiz/Snyk-style overview
(severity tiles + a server table + per-server finding detail) — but every verdict is GROUND
TRUTH (the attack fired or it didn't, zero false positives), and every row carries a signed,
offline-verifiable attestation no competitor's dashboard produces.

    mcp-rt serve                       # http://127.0.0.1:8900   (data in ./mcprt_data)
    mcp-rt serve --port 9000 --data /srv/mcprt/data

Storage is a plain folder of attestations for now (host-anywhere, no DB). Postgres + org_id +
multi-tenant auth is the next step, for the VPS/SaaS deployment — this is the local test rig.
"""
from __future__ import annotations

import argparse
import json
import threading
import uuid
from pathlib import Path

from mcp_rt import attest

# Jobs live in memory (single-process local rig); a real deployment moves these to the DB/queue.
_JOBS: dict[str, dict] = {}
_DATA = Path("mcprt_data")


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("mcp-rt")
    except Exception:  # noqa: BLE001
        return "0+unknown"


def _slug(target: str) -> str:
    import re
    return (re.sub(r"[^a-zA-Z0-9]+", "-", target).strip("-").lower() or "target")[:60]


def _run_job(job_id: str, target: str, tier: str, agent: bool) -> None:
    """Background worker: scan -> sign -> persist. Updates _JOBS[job_id] in place."""
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
        key = attest.load_or_create_key()
        env = attest.sign(claim, key)
        slug = _slug(target)
        _DATA.mkdir(parents=True, exist_ok=True)
        (_DATA / f"{slug}.attestation.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
        (_DATA / f"{slug}.report.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        (_DATA / f"{slug}.badge.svg").write_text(attest.make_badge(env), encoding="utf-8")
        _JOBS[job_id] = {"status": "done", "target": target, "slug": slug,
                         "verdict": claim["scan"]["verdict"], "tier": tier}
    except Exception as exc:  # noqa: BLE001 — surface the failure to the dashboard, don't crash the server
        _JOBS[job_id] = {"status": "error", "target": target, "error": str(exc)[:300]}


def _server_rows() -> list[dict]:
    """Verify every stored attestation and return dashboard rows (ground-truth verdicts)."""
    rows = []
    for f in sorted(_DATA.glob("*.attestation.json")):
        try:
            env = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ok, _ = attest.verify(env)
        c = env.get("claim", {}); s = c.get("scan", {})
        rows.append({
            "slug": f.name[:-len(".attestation.json")],
            "target": c.get("target", {}).get("spec", "?"),
            "verdict": s.get("verdict", "?"), "tier": s.get("tier", "basic"),
            "classes": s.get("classes_tested", []), "components": s.get("components", {}),
            "findings": c.get("finding_summary", {}), "scanned": c.get("scanned_at", "?"),
            "signed_valid": ok,
        })
    return rows


def create_app(data_dir: Path):
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    global _DATA
    _DATA = data_dir
    _DATA.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="mcp-rt", docs_url="/api/docs")
    here = Path(__file__).parent

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return (here / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/verify", response_class=HTMLResponse)
    def verify_page():
        return (here / "verify.html").read_text(encoding="utf-8")

    @app.post("/api/scan")
    async def start_scan(body: dict):
        target = (body or {}).get("target", "").strip()
        if not target:
            return JSONResponse({"error": "target required"}, status_code=400)
        tier = "deep" if (body or {}).get("deep") else "basic"
        agent = bool((body or {}).get("agent_redteam"))
        job_id = uuid.uuid4().hex[:12]
        _JOBS[job_id] = {"status": "running", "target": target, "tier": tier}
        threading.Thread(target=_run_job, args=(job_id, target, tier, agent), daemon=True).start()
        return {"job_id": job_id}

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str):
        return _JOBS.get(job_id, {"status": "unknown"})

    @app.get("/api/servers")
    def servers():
        rows = _server_rows()
        tiles = {"CLEAN": 0, "VULNERABLE": 0, "INCONCLUSIVE": 0}
        for r in rows:
            tiles[r["verdict"]] = tiles.get(r["verdict"], 0) + 1
        return {"servers": rows, "tiles": tiles, "total": len(rows)}

    @app.get("/data/{name}")
    def data_file(name: str):
        f = (_DATA / name).resolve()
        if _DATA.resolve() not in f.parents or not f.exists():   # no path escape
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(f)

    return app


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt serve",
                                description="Run the mcp-rt scan service + dashboard (localhost or VPS).")
    p.add_argument("--port", type=int, default=8900)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--data", default="mcprt_data", help="folder for stored attestations")
    args = p.parse_args(argv)
    import uvicorn
    app = create_app(Path(args.data))
    print(f"mcp-rt dashboard → http://{args.host}:{args.port}   (data: {Path(args.data).resolve()})")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
