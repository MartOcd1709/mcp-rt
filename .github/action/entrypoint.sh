#!/bin/bash
set -euo pipefail

FAIL_ON="${1:-critical}"
SARIF_PATH="${2:-mcp-rt.sarif}"
CONFIG="${3:-}"
ATTEST_DIR="${4:-mcp-rt-attestations}"

echo "🛡️  mcp-rt — MCP Security Scan (fail-on=$FAIL_ON)"

ARGS=(--fail-on "$FAIL_ON" --sarif "$SARIF_PATH" --attest "$ATTEST_DIR")
if [ -n "$CONFIG" ]; then
  # shellcheck disable=SC2206
  ARGS+=(--config $CONFIG)
fi
# Sign with a stable key from a repo secret if provided (MCPRT_SIGNING_KEY = a PEM private key),
# so attestations across PRs share one verifiable signer. Otherwise an ephemeral per-run key.
if [ -n "${MCPRT_SIGNING_KEY:-}" ]; then
  printf '%s' "$MCPRT_SIGNING_KEY" > /tmp/mcprt_key.pem
  chmod 600 /tmp/mcprt_key.pem
  ARGS+=(--key /tmp/mcprt_key.pem)
fi

# mcp-rt ci writes SARIF + per-server signed attestations, prints the outputs, exits per --fail-on.
set +e
OUTPUT="$(mcp-rt ci "${ARGS[@]}")"
CODE=$?
set -e
echo "$OUTPUT"

# Surface GitHub Action outputs
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "$OUTPUT" | grep -E '^(findings-count|sarif-path|attestations|attest-dir)=' >> "$GITHUB_OUTPUT" || true
fi

# PR-visible job summary
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  FC="$(echo "$OUTPUT" | sed -n 's/^findings-count=//p')"
  AC="$(echo "$OUTPUT" | sed -n 's/^attestations=//p')"
  {
    echo "## 🛡️ mcp-rt — Ground-Truth MCP Security Scan"
    echo ""
    echo "- **Findings:** ${FC:-0}  (gate: \`--fail-on $FAIL_ON\`)"
    echo "- **Signed attestations:** ${AC:-0}  — in \`$ATTEST_DIR/\`, each offline-verifiable (\`mcp-rt attest --verify\`)"
    echo "- SARIF uploaded to the **Security** tab."
    echo ""
    if [ "$CODE" -ne 0 ]; then echo "❌ **Gate failed** — a finding at or above the threshold was reproduced."; \
      else echo "✅ **Gate passed** — no finding at or above the threshold."; fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

exit $CODE
