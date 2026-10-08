"""run_probe — drive a headless Claude Code task against probe-server and report
which optional MCP channels the agent actually exercised. INSTRUMENTATION ONLY.

  python run_probe.py --selftest   # validate the probe with an in-process client (no agent, no spend)
  python run_probe.py              # run a real headless Claude Code task and summarize
"""
import argparse
import asyncio
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from pydantic import AnyUrl

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent.parent
VENV_PY = str(PROJECT / ".venv" / "bin" / "python")
SERVER = str(HERE / "probe_server.py")
LOG = str(HERE / "probe_log.jsonl")
TRANSCRIPT_FILE = str(HERE / "last_run_transcript.txt")
SUMMARY_FILE = str(HERE / "last_run_summary.txt")

# A realistic task — NOT "exercise channel X". If the agent organically reaches for
# autocompletion, subscriptions, or progress, that is the signal we want to capture.
TASK = (
    "You have a diagnostic MCP server called 'probe' available. Use its tools to look "
    "up a couple of topics (for example 'mcp' and 'python') and give me a short summary "
    "of what you found. If the server offers status updates or argument autocompletion, "
    "feel free to use them."
)


def _load_log(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _summarize(recs: list[dict], transcript: str) -> str:
    """Build the channel summary, print it, and return it as text (also saved to disk)."""
    by: dict[str, list[dict]] = {}
    for r in recs:
        by.setdefault(r["method"], []).append(r)
    out: list[str] = []

    def line(name: str, invoked: str, count: int, first, note: str = "") -> None:
        first_s = json.dumps(first) if first not in (None, "-") else "-"
        out.append(f"{name:30} {invoked:20} {count:<6} {first_s[:60]} {note}")

    out.append(f"\n{'Channel':30} {'Status':20} {'Count':6} First params seen")
    out.append("-" * 100)

    c1 = by.get("completion/complete", [])
    line("1. completion/complete", "YES" if c1 else "no", len(c1), c1[0]["params"] if c1 else "-")

    c2 = by.get("resources/subscribe", [])
    line("2. resource subscription", "YES" if c2 else "no", len(c2), c2[0]["params"] if c2 else "-")

    sent = by.get("result/_meta.sent", [])
    ingested = any(str(s["params"].get("probe_marker", "")) in transcript for s in sent)
    line("3. _meta result passthrough",
         f"sent={len(sent)} ingest={'YES' if ingested else 'no'}",
         len(sent), sent[0]["params"] if sent else "-",
         note="(ingest = marker echoed in agent text)")

    calls = by.get("tools/call", [])
    tok = [c for c in calls if c["params"].get("progressToken") is not None]
    prog = by.get("progress/ingestion_probe.sent", [])
    marker_in = any(str(p["params"].get("marker", "")) in transcript for p in prog)
    echo_in = any(str(p["params"].get("echo_word", "")) in transcript for p in prog)
    status = "YES" if tok else "no"
    if tok:
        status += f" ingest={'YES' if marker_in else 'no'}/act={'YES' if echo_in else 'no'}"
    line("4. progress notifications", status, len(tok),
         tok[0]["params"] if tok else "-",
         note="(ingest=progress text reached model; act=model followed it)")

    out.append("-" * 100)
    out.append(f"tool calls total: {len(calls)}   |   log: {LOG}")
    if not calls:
        out.append("NOTE: the agent never called a tool — check the CLI ran and the server loaded.")
    text = "\n".join(out)
    print(text)
    return text


def _mcp_config(log_path: str) -> str:
    cfg = {"mcpServers": {"probe": {"command": VENV_PY, "args": [SERVER],
                                    "env": {"PROBE_LOG": log_path}}}}
    fd, path = tempfile.mkstemp(prefix="probe_mcp_", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(cfg, fh)
    return path


def _argv_for(client: str, log_path: str) -> list[str]:
    if client == "claude-code":
        cfg = _mcp_config(log_path)
        return ["claude", "-p", TASK, "--mcp-config", cfg,
                "--dangerously-skip-permissions", "--output-format", "text"]
    # Codex: inject the stdio server via documented -c flags (same pattern the
    # repo's CodexClient uses), pointing PROBE_LOG at our log.
    return ["codex", "exec",
            "-c", f'mcp_servers.probe.command="{VENV_PY}"',
            "-c", f'mcp_servers.probe.args=["{SERVER}"]',
            "-c", f'mcp_servers.probe.env.PROBE_LOG="{log_path}"',
            "--dangerously-bypass-approvals-and-sandbox", TASK]


def run_agent(client: str, timeout: int) -> int:
    if os.path.exists(LOG):
        os.unlink(LOG)
    argv = _argv_for(client, LOG)
    print(f"Running headless {client} against probe-server...")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        transcript = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except FileNotFoundError:
        print(f"'{argv[0]}' CLI not found on PATH. Use --selftest to validate the probe without an agent.")
        return 1
    except subprocess.TimeoutExpired as exc:
        transcript = f"[timeout after {timeout}s] {exc}"
    # Persist the raw transcript + summary for EVERY run/client so verdicts are
    # always recoverable from disk (no more "it only printed to the terminal").
    header = f"# client={client}  ts={time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    with open(TRANSCRIPT_FILE, "w", encoding="utf-8") as fh:
        fh.write(header + transcript)
    print("\n--- agent transcript (truncated) ---")
    print(transcript[:1500])
    summary = _summarize(_load_log(LOG), transcript)
    with open(SUMMARY_FILE, "w", encoding="utf-8") as fh:
        fh.write(header + summary + "\n")
    print(f"\nSaved: {TRANSCRIPT_FILE}\nSaved: {SUMMARY_FILE}")
    return 0


async def _selftest() -> int:
    """Exercise every channel with an in-process MCP client — proves the instrument
    records each one, with no agent and no network."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    if os.path.exists(LOG):
        os.unlink(LOG)
    params = StdioServerParameters(command=VENV_PY, args=[SERVER],
                                   env={**os.environ, "PROBE_LOG": LOG})
    progress_seen: list[float] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            await s.list_tools()

            async def on_progress(progress: float, total: float | None, message: str | None) -> None:
                progress_seen.append(progress)

            await s.call_tool("lookup_fact", {"topic": "mcp"}, progress_callback=on_progress)
            from mcp.types import PromptReference
            await s.complete(PromptReference(type="ref/prompt", name="research_helper"),
                             {"name": "topic", "value": "m"})
            await s.subscribe_resource(AnyUrl("probe://status"))
            await asyncio.sleep(2.0)  # let the resource_updated pushes fire

    recs = _load_log(LOG)
    methods = {r["method"] for r in recs}
    for required in ("tools/call", "completion/complete", "resources/subscribe"):
        assert required in methods, f"channel NOT recorded: {required}"
    assert progress_seen, "no progress notifications received by the client"
    assert any(r["method"] == "resources/updated.sent" for r in recs), "no resource_updated pushed"
    assert any(r["method"] == "result/_meta.sent" for r in recs), "no _meta attached to result"
    print("SELFTEST OK — all four channels are exercised and logged.")
    print(f"  progress notifications received: {len(progress_seen)}")
    print(f"  log records: {len(recs)}  ({sorted(methods)})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true",
                    help="Validate the probe with an in-process client (no agent, no spend).")
    ap.add_argument("--client", choices=["claude-code", "codex"], default="claude-code",
                    help="Which headless agent to measure (default: claude-code).")
    ap.add_argument("--timeout", type=int, default=180, help="Agent timeout, seconds.")
    args = ap.parse_args()
    if args.selftest:
        return asyncio.run(_selftest())
    return run_agent(args.client, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
