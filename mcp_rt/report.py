"""Reporter — the resilience matrix as terminal, JSON, and HTML artifacts."""
import html
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table


def _status(r: dict) -> str:
    if r.get("error"):
        return "ERROR"
    return "VULNERABLE" if r["vulnerable"] else "RESILIENT"


def print_matrix(results: list[dict]):
    console = Console()
    table = Table(title="mcp-rt — MCP Client Resilience Matrix")
    table.add_column("Client", style="bold")
    table.add_column("Attack")
    table.add_column("MCP-38")
    table.add_column("Verdict")
    table.add_column("Evidence")
    for r in results:
        if r.get("error"):
            verdict = "[bold yellow]ERROR[/]"
            evidence = r["error"][:40]
        elif r["vulnerable"]:
            verdict = "[bold red]VULNERABLE[/]"
            signals = []
            if r["detail"]["read"]:
                signals.append("read honeytoken")
            if r["detail"]["exfil"]:
                signals.append("exfil->canary")
            evidence = ", ".join(signals)
        else:
            verdict = "[bold green]RESILIENT[/]"
            evidence = "no canary signal"
        table.add_row(r["client"], r["attack"], r["mcp38"], verdict, evidence)
    console.print(table)


def write_json(results: list[dict], path: str) -> None:
    Path(path).write_text(json.dumps(results, indent=2, default=str))


_HTML_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3;margin:2rem}
h1{font-size:1.4rem}.sub{color:#8b949e;margin-bottom:1.2rem}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border:1px solid #30363d;padding:.5rem .7rem;text-align:left;vertical-align:top}
th{background:#161b22}
.VULNERABLE{color:#ff6b6b;font-weight:700}.RESILIENT{color:#3fb950;font-weight:700}.ERROR{color:#d29922;font-weight:700}
details{color:#8b949e}pre{white-space:pre-wrap;background:#161b22;padding:.5rem;border-radius:6px;font-size:.8rem}
"""


def write_html(results: list[dict], path: str, title: str = "mcp-rt — MCP Client Resilience Matrix") -> None:
    rows = []
    for r in results:
        st = _status(r)
        if st == "VULNERABLE":
            ev = ", ".join(
                s for s, on in [("read honeytoken", r["detail"]["read"]),
                                ("exfil→canary", r["detail"]["exfil"])] if on)
        elif st == "ERROR":
            ev = html.escape((r.get("error") or "")[:80])
        else:
            ev = "no canary signal"
        transcript = html.escape("\n".join(r.get("transcript", [])))
        rows.append(
            f'<tr><td>{html.escape(r["client"])}</td>'
            f'<td>{html.escape(r["attack"])}</td>'
            f'<td>{html.escape(r["mcp38"])}</td>'
            f'<td class="{st}">{st}</td><td>{ev}</td>'
            f'<td><details><summary>transcript</summary><pre>{transcript}</pre></details></td></tr>'
        )
    doc = (
        f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
        f"<style>{_HTML_CSS}</style></head><body>"
        f"<h1>{html.escape(title)}</h1>"
        f"<div class='sub'>Behavioral verdicts via honeytoken ground-truth · MCP-38 mapped</div>"
        f"<table><tr><th>Client</th><th>Attack</th><th>MCP-38</th><th>Verdict</th>"
        f"<th>Evidence</th><th>Detail</th></tr>{''.join(rows)}</table></body></html>"
    )
    Path(path).write_text(doc)
