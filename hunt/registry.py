"""`mcp-rt registry` — build a static attestation registry from a folder of attestations.

Point it at a directory of ``*.attestation.json`` and it renders a self-contained ``index.html``
listing each server's signed verdict, with a per-attestation permalink into ``verify.html?att=…``
(which re-checks the Ed25519 signature in the browser). No backend: host the folder anywhere
(GitHub Pages, S3, a static server). Each row's signature is verified at build time, so a tampered
file shows up as INVALID rather than being listed as trustworthy.

    mcp-rt registry --dir ./attestations            # writes ./attestations/index.html (+ verify.html)

This is the compounding trust surface — the more servers attested, the more adopters rely on it.
"""
from __future__ import annotations

import argparse
import datetime
import html
import json
import sys
from pathlib import Path

from mcp_rt import attest

_VERIFY_SRC = Path(__file__).with_name("verify.html")
_COLOR = {"CLEAN": "#2e9e3f", "VULNERABLE": "#c62828"}


def _rows(dir_: Path) -> list[dict]:
    rows = []
    for f in sorted(dir_.glob("*.attestation.json")):
        try:
            env = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ok, _ = attest.verify(env)
        c = env.get("claim", {}); s = c.get("scan", {})
        rows.append({
            "file": f.name, "valid": ok,
            "target": c.get("target", {}).get("spec", "?"),
            "verdict": s.get("verdict", "?"), "tier": s.get("tier", "basic"),
            "scanned": c.get("scanned_at", "?"),
            "signer": (env.get("sig", {}).get("public_key", "") or "")[:16],
        })
    return rows


def render(rows: list[dict], title: str) -> str:
    e = html.escape
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    trs = []
    for r in rows:
        vcol = _COLOR.get(r["verdict"], "#8a8a8a")
        sig = ('<span style="color:#7ee096">✓ valid</span>' if r["valid"]
               else '<span style="color:#ff8f8f">✗ INVALID</span>')
        link = f'verify.html?att={e(r["file"])}'
        trs.append(
            f'<tr><td><a href="{link}">{e(r["target"])}</a></td>'
            f'<td style="color:{vcol};font-weight:600">{e(r["verdict"])}</td>'
            f'<td>{e(r["tier"])}</td><td>{e(r["scanned"])}</td>'
            f'<td class="mono">{e(r["signer"])}…</td><td>{sig}</td></tr>'
        )
    clean = sum(1 for r in rows if r["verdict"] == "CLEAN" and r["valid"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(title)}</title>
<style>
 body{{margin:0;background:#0e1116;color:#e6edf3;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:32px 16px}}
 main{{max-width:900px;margin:0 auto}} h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#9aa7b4;font-size:13px;margin:0 0 20px}}
 table{{width:100%;border-collapse:collapse;font-size:13px;border:1px solid #2a313c;border-radius:10px;overflow:hidden}}
 th,td{{padding:10px 14px;text-align:left;border-top:1px solid #2a313c}} th{{background:#161b22;color:#9aa7b4;font-weight:600;border-top:0}}
 tr:hover td{{background:#131820}} a{{color:#4c8bf5;text-decoration:none}} a:hover{{text-decoration:underline}}
 .mono{{font-family:ui-monospace,Menlo,monospace}} .foot{{color:#9aa7b4;font-size:12px;margin-top:16px}}
</style></head><body><main>
 <h1>🛡️ {e(title)}</h1>
 <p class="sub">{len(rows)} attestation(s) · {clean} verified CLEAN · generated {e(now)}. Each verdict is a
 signed, reproducible proof — click a server to re-verify its Ed25519 signature in your browser.</p>
 <table><thead><tr><th>Server</th><th>Verdict</th><th>Tier</th><th>Scanned</th><th>Signer</th><th>Signature</th></tr></thead>
 <tbody>{''.join(trs) or '<tr><td colspan="6" style="color:#9aa7b4">No attestations in this folder yet.</td></tr>'}</tbody></table>
 <p class="foot">Built by <code>mcp-rt registry</code>. Signatures verified at build time. Learn more:
 <a href="https://github.com/MartOcd1709/mcp-rt">github.com/MartOcd1709/mcp-rt</a></p>
</main></body></html>"""


def build(dir_: Path, title: str) -> Path:
    rows = _rows(dir_)
    (dir_ / "index.html").write_text(render(rows, title), encoding="utf-8")
    if not (dir_ / "verify.html").exists():          # ensure permalinks resolve
        (dir_ / "verify.html").write_text(_VERIFY_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    return dir_ / "index.html"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt registry",
                                description="Build a static attestation registry (index.html) from a folder of attestations.")
    p.add_argument("--dir", required=True, help="folder containing *.attestation.json")
    p.add_argument("--title", default="MCP Attestation Registry", help="page title")
    args = p.parse_args(argv)
    d = Path(args.dir)
    if not d.is_dir():
        print(f"not a directory: {d}", file=sys.stderr); return 2
    out = build(d, args.title)
    n = len(list(d.glob("*.attestation.json")))
    print(f"registry: {out}  ({n} attestation(s))")
    print(f"host the folder statically; open index.html, click a server to verify.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
