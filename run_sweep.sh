#!/usr/bin/env bash
#
# run_sweep.sh — one-command long-tail MCP vulnerability sweep.
#
# Discovers low-download, niche MCP servers (shell/exec/git/fs/sql/fetch), installs each
# locally, runs the full ground-truth benchmark (6 classes + OWASP MCP Top 10 posture),
# preserves a report per server, and records every result to the findings ledger.
#
# Run on a box with reliable npm + network (a VPS). In a throttled sandbox expect many
# INCONCLUSIVE. GUARDRAILS: local, open-source servers only; synthetic probes only;
# responsibly disclose any confirmed finding BEFORE any public listing (see the mcp-hunt skill).
#
# Usage:   ./run_sweep.sh [CAP] [TIMEOUT_S] [MAX_DOWNLOADS]
#   CAP            max servers to test            (default 40)
#   TIMEOUT_S      per-server scan timeout        (default 120)
#   MAX_DL         long-tail threshold, dl/week   (default 2000; lower = deeper tail)
#
#   ./run_sweep.sh                 # 40 long-tail servers
#   ./run_sweep.sh 60 150 800      # 60 servers, deeper tail, longer timeout
#   ./run_sweep.sh --discover      # just list what WOULD be tested (no install/scan)
set -euo pipefail
cd "$(dirname "$0")"

PY=".venv/bin/python"; [ -x "$PY" ] || PY="$(command -v python3)"

# preflight: dependencies the probes/targets need
command -v npx  >/dev/null || { echo "need node/npx on PATH"; exit 1; }
command -v uvx  >/dev/null || echo "note: uvx not found — python (uvx) servers will be skipped"
"$PY" -c "import mcp" 2>/dev/null || { echo "need the mcp SDK in $PY (pip install mcp rich)"; exit 1; }

mkdir -p /tmp/fs_allowed && echo "allowed dir" > /tmp/fs_allowed/readme.txt
[ -d /tmp/gitrepo/.git ] || { mkdir -p /tmp/gitrepo && git init -q /tmp/gitrepo; }

if [ "${1:-}" = "--discover" ]; then
  exec "$PY" -m hunt.sweep --cap "${2:-40}" --max-downloads "${3:-2000}" --discover-only
fi

CAP="${1:-40}"; TIMEOUT="${2:-120}"; MAXDL="${3:-2000}"
mkdir -p hunt/logs
TS="$(date +%Y%m%d_%H%M%S)"; LOG="hunt/logs/sweep_${TS}.log"

echo "mcp-rt long-tail sweep | cap=$CAP timeout=${TIMEOUT}s max_downloads=${MAXDL}/wk"
echo "log: $LOG"
"$PY" -m hunt.sweep --cap "$CAP" --timeout "$TIMEOUT" --max-downloads "$MAXDL" 2>&1 | tee "$LOG"

echo
echo "=== ledger ==="
"$PY" -c "from hunt.findings_db import DB; print(DB().summary())"
echo "reports: hunt/reports/   evidence: hunt/logs/   full log: $LOG"
echo "triage any VULNERABLE -> dedup -> ground-truth reproduce -> private GHSA before listing."
