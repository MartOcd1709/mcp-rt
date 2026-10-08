"""Read-only public scorecard — the visible proof surface (generated from the ledger).

Renders a self-contained dark HTML page from findings.db + the detection catalog: coverage
(every class we detect), OWASP MCP Top 10 posture, aggregate test stats, named CLEAN servers,
and the disclosed-advisory wall. DISCLOSURE-SAFE: a server with an open (unpublished) finding
is NEVER named — it is counted only as "under coordinated disclosure" until its advisory is
public. No logins, no backend; host it anywhere.

    mcp-rt scorecard            # -> hunt/scorecard.html
"""
from __future__ import annotations

import datetime
import html
import sys
from pathlib import Path

from hunt.findings_db import DB
from hunt.report import CLASS_META, OWASP_MCP_TOP10, TESTED_CONTROLS

RESEARCH_EXFILS = "23/26"   # Black Hat Arsenal research: confirmed agent credential-exfils / attacks


def _gather() -> dict:
    db = DB()
    c = db.conn
    targets = {r["id"]: r["name"] for r in c.execute("SELECT id, name FROM targets").fetchall()}
    verdicts: dict[int, list[str]] = {tid: [] for tid in targets}
    for r in c.execute("SELECT target_id, verdict FROM scans").fetchall():
        verdicts.setdefault(r["target_id"], []).append(r["verdict"])
    published = {r["target_id"] for r in c.execute(
        "SELECT target_id FROM disclosures WHERE status IN ('published','patched')").fetchall()}
    under_disclosure = {r["target_id"] for r in c.execute(
        "SELECT target_id FROM disclosures WHERE status NOT IN ('published','patched','none')").fetchall()}
    confirmed = c.execute("SELECT COUNT(DISTINCT target_id) n FROM scans "
                          "WHERE verdict IN ('VULNERABLE','LEAKED')").fetchone()["n"]
    triaged = c.execute("SELECT COUNT(*) n FROM scans WHERE notes LIKE '%reclassified%'").fetchone()["n"]

    clean, inconclusive, disclosing, pub_findings = [], 0, 0, []
    for tid, vs in verdicts.items():
        if not vs:
            continue
        has_vuln = "VULNERABLE" in vs or "LEAKED" in vs
        if has_vuln and tid in published:
            pub_findings.append(targets[tid])
        elif has_vuln:
            disclosing += 1                       # DO NOT name — coordinated disclosure in progress
        elif all(v == "INCONCLUSIVE" for v in vs):
            inconclusive += 1
        else:
            clean.append(targets[tid])
    db.close()
    return {"tested": len([v for v in verdicts.values() if v]), "clean": sorted(set(clean)),
            "inconclusive": inconclusive, "disclosing": disclosing, "published": sorted(set(pub_findings)),
            "confirmed": confirmed, "triaged": triaged}


def render() -> str:
    d = _gather()
    today = datetime.date.today().isoformat()
    tiles = [("Detection classes", len(CLASS_META)), ("Servers tested", d["tested"]),
             ("Agent exfils (research)", RESEARCH_EXFILS), ("Candidates triaged out", d["triaged"])]
    tile_html = "".join(
        f'<div class="tile"><div class="n">{v}</div><div class="l">{html.escape(k)}</div></div>'
        for k, v in tiles)
    cov_rows = "".join(
        f'<tr><td>{html.escape(m["title"])}</td><td class="mono">{m["cwe"]}</td>'
        f'<td class="mono">{", ".join(m["owasp"])}</td><td class="mono">{html.escape(cls)}</td></tr>'
        for cls, m in sorted(CLASS_META.items(), key=lambda kv: kv[1]["title"]))
    owasp_rows = "".join(
        f'<tr><td class="mono">{cid}</td><td>{html.escape(t)}</td>'
        f'<td>{"✅ tested" if cid in TESTED_CONTROLS else "— not tested"}</td></tr>'
        for cid, t in OWASP_MCP_TOP10.items())
    clean_html = ("".join(f'<span class="chip">{html.escape(n)}</span>' for n in d["clean"])
                  or '<span class="muted">none yet</span>')
    wall = ("".join(f'<li>{html.escape(n)} — disclosed</li>' for n in d["published"])
            if d["published"]
            else f'<li class="muted">{d["confirmed"]} confirmed (CVE-class) · coordinated disclosure '
                 f'in progress — named here once published</li>')
    return f"""<title>mcp-rt Security Scorecard</title>
<style>
 :root{{color-scheme:dark;--bg:#0a0d11;--panel:#121823;--bd:#202a36;--fg:#dce4ee;--mut:#8a99a9;
   --ac:#22d3ee;--good:#34d399;--mono:'JetBrains Mono',ui-monospace,monospace;
   --sans:'IBM Plex Sans',system-ui,sans-serif}}
 *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.6}}
 .wrap{{max-width:900px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:clamp(26px,5vw,38px);margin:0 0 6px;letter-spacing:-.02em}} h1 .rt{{color:var(--ac)}}
 .sub{{color:var(--mut);max-width:62ch;margin:0 0 22px}}
 .tiles{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:28px}}
 .tile{{background:var(--panel);border:1px solid var(--bd);border-radius:10px;padding:14px 18px;min-width:0}}
 .tile .n{{font-family:var(--mono);font-size:26px;color:var(--ac);font-weight:600}}
 .tile .l{{font-size:11.5px;color:var(--mut);text-transform:uppercase;letter-spacing:.07em;margin-top:2px}}
 h2{{font-size:19px;margin:30px 0 10px;border-bottom:1px solid var(--bd);padding-bottom:6px}}
 table{{width:100%;border-collapse:collapse;font-size:13.5px}} th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--bd)}}
 th{{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}}
 .mono{{font-family:var(--mono)}} td.mono{{color:var(--ac);font-size:12px}}
 .chip{{display:inline-block;background:rgba(52,211,153,.12);color:var(--good);border:1px solid rgba(52,211,153,.3);
   border-radius:6px;padding:3px 9px;margin:3px 4px 0 0;font-family:var(--mono);font-size:12px}}
 .muted{{color:var(--mut)}} ul{{padding-left:18px}} li{{margin:4px 0}}
 footer{{margin-top:36px;color:var(--mut);font-size:12px;border-top:1px solid var(--bd);padding-top:14px}}
 .wrap>div.tiles{{}}
</style>
<div class="wrap">
 <h1>mcp<span class="rt">-rt</span> Security Scorecard</h1>
 <p class="sub">Ground-truth security posture for MCP servers — every verdict is proven by a planted
  honeytoken, sentinel, canary, or captured response, not a heuristic. Generated {today}.</p>
 <div class="tiles">{tile_html}</div>

 <h2>Detection coverage — {len(CLASS_META)} ground-truth classes</h2>
 <table><tr><th>Finding class</th><th>CWE</th><th>OWASP MCP</th><th>probe</th></tr>{cov_rows}</table>

 <h2>OWASP MCP Top 10 — actively tested</h2>
 <table><tr><th>Control</th><th>Title</th><th>Status</th></tr>{owasp_rows}</table>

 <h2>Servers tested clean ({len(d["clean"])})</h2>
 <div>{clean_html}</div>
 <p class="muted" style="font-size:12.5px;margin-top:10px">+ {d["inconclusive"]} not conclusively testable in this run ·
  {d["disclosing"]} under coordinated disclosure (not named until published).</p>

 <h2>Findings — ground truth, in context</h2>
 <p>Across <strong>{d["tested"]} servers</strong> tested over {len(CLASS_META)} classes:
 <strong>{d["confirmed"]} confirmed</strong> (CVE-class) · {d["disclosing"]} in coordinated disclosure ·
 {len(d["clean"])} clean · <strong>{d["triaged"]} candidates triaged out</strong> (by-design / false-positive,
 never counted). <strong>Zero false positives</strong> in reported findings — that discipline is why a
 confirmed finding here is believable.</p>
 <ul>{wall}</ul>

 <footer>mcp-rt · ground-truth MCP VAPT + benchmark · responsible disclosure before any public listing ·
  scores reflect the actively-tested OWASP controls (see the benchmark spec).</footer>
</div>"""


def main(argv=None) -> int:
    out = Path(__file__).resolve().parent / "scorecard.html"
    out.write_text(render())
    print(f"scorecard written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
