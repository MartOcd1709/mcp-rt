#!/bin/bash
set -euo pipefail

FAIL_ON="${1:-critical}"
SARIF_PATH="${2:-mcp-rt.sarif}"
CONFIG="${3:-}"

echo "🛡️  mcp-rt — MCP Security Scan (fail-on=$FAIL_ON)"

ARGS=(--fail-on "$FAIL_ON" --sarif "$SARIF_PATH")
if [ -n "$CONFIG" ]; then
  # shellcheck disable=SC2206
  ARGS+=(--config $CONFIG)
fi

# mcp-rt ci writes the SARIF, prints findings-count/sarif-path, and exits non-zero per --fail-on.
set +e
OUTPUT="$(mcp-rt ci "${ARGS[@]}")"
CODE=$?
set -e
echo "$OUTPUT"

# Surface GitHub Action outputs
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "$OUTPUT" | grep -E '^(findings-count|sarif-path)=' >> "$GITHUB_OUTPUT" || true
fi

exit $CODE
