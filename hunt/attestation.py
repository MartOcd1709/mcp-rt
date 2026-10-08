"""`mcp-rt attest` — scan a server and emit a signed, offline-verifiable attestation.

    mcp-rt attest --target-stdio "npx -y some-mcp-server"   # scan -> signed attestation + badge
    mcp-rt attest --verify some-mcp-server.attestation.json # offline-verify (only needs the file)

The scan reuses the direct-probe path (hunt.report.run_full_scan) — no agent binary needed —
and mcp_rt.attest does the signing/verifying. Everything is local: nothing here phones home;
publishing an attestation anywhere is the operator's separate choice.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import shlex
import sys
from pathlib import Path

from mcp_rt import attest
from hunt.report import run_full_scan


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("mcp-rt")
    except Exception:  # noqa: BLE001 — not installed as a dist (editable/source run)
        return "0+unknown"


def _slug(target: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9]+", "-", target).strip("-").lower() or "target"
    return base[:60]


def _do_verify(path: str) -> int:
    try:
        envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read attestation: {exc}", file=sys.stderr)
        return 2
    ok, reason = attest.verify(envelope)
    claim = envelope.get("claim", {})
    print(f"verify: {'VALID' if ok else 'INVALID'} — {reason}")
    if ok:
        scan = claim.get("scan", {})
        print(f"  target : {claim.get('target', {}).get('spec', '?')}")
        print(f"  verdict: {scan.get('verdict', '?')}  (mcp-rt {scan.get('mcp_rt_version', '?')})")
        print(f"  scanned: {claim.get('scanned_at', '?')}  ·  issued: {claim.get('issued_at', '?')}")
        print(f"  signer : {envelope.get('sig', {}).get('public_key', '?')[:16]}…")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="mcp-rt attest",
        description="Scan an MCP server and emit a signed, offline-verifiable ground-truth attestation.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--target-stdio", metavar="CMD", help='local server to scan, e.g. "npx some-mcp-server"')
    g.add_argument("--verify", metavar="FILE", help="offline-verify an existing .attestation.json and exit")
    p.add_argument("--out", default=".", metavar="DIR", help="output directory (default: cwd)")
    p.add_argument("--key", default=str(attest._DEFAULT_KEY), metavar="PEM",
                   help="signing key path (created on first use)")
    p.add_argument("--no-badge", action="store_true", help="skip writing the SVG badge")
    p.add_argument("--no-verify-page", action="store_true",
                   help="skip copying the self-contained HTML verify page")
    p.add_argument("--json", action="store_true", help="print the signed attestation to stdout")
    args = p.parse_args(argv)

    if args.verify:
        return _do_verify(args.verify)

    report = asyncio.run(run_full_scan(shlex.split(args.target_stdio)))
    claim = attest.build_claim(report, capture="direct-probe", mcp_rt_version=_version())
    key = attest.load_or_create_key(args.key)
    envelope = attest.sign(claim, key)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    slug = _slug(args.target_stdio)
    att_path = out / f"{slug}.attestation.json"
    rep_path = out / f"{slug}.report.json"        # the evidence the attestation digests
    att_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    rep_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not args.no_badge:
        (out / f"{slug}.badge.svg").write_text(attest.make_badge(envelope), encoding="utf-8")
    if not args.no_verify_page:
        src = Path(__file__).with_name("verify.html")   # self-contained, host-anywhere
        (out / "verify.html").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    if args.json:
        print(json.dumps(envelope, indent=2))
    else:
        print(f"verdict: {report['verdict']}")
        print(f"signed attestation: {att_path}")
        print(f"evidence report:    {rep_path}")
        if not args.no_badge:
            print(f"badge:              {out / f'{slug}.badge.svg'}")
        if not args.no_verify_page:
            print(f"verify page:        {out / 'verify.html'}  (open in a browser, drop the .json)")
        print(f"verify offline:     mcp-rt attest --verify {att_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
