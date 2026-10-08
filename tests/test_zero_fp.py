"""Zero-false-positive hardening of the generic file-read taint path.

A bare file-read token becomes a taint SOURCE only if it is secret-shaped (long, mixed
digit+letter, high entropy). Word-like filenames must not become sources — otherwise an
incidental match in a benign egress payload would manufacture a false LEAKED. Planted
honeytoken markers stay caught by their own regex and must still flag regardless of this gate.
"""
from mcp_rt.detect.taint_monitor import (
    Egress,
    SessionTrace,
    ToolCall,
    _secret_like,
    analyze_session,
)


def test_real_secrets_pass_the_gate():
    for tok in ("AKIAIOSFODNN7EXAMPLE", "sk-proj-Ab12Cd34Ef56Gh78",
                "aKf93Jx82Lp01Qmz7Yt4", "0123456789abcdef0123456789abcdef"):
        assert _secret_like(tok), tok


def test_wordlike_and_short_tokens_are_rejected():
    for tok in ("configuration", "deployment-guide-readme", "workspace_config_json",
                "en-US-region-east", "README", "node_modules"):
        assert not _secret_like(tok), tok


def test_wordlike_file_token_to_undeclared_host_is_not_flagged():
    # A benign server reads a config file and some innocuous word lands in outbound telemetry.
    # Pre-hardening this manufactured a LEAKED; it must now stay CLEAN.
    trace = SessionTrace(
        tool_calls=[ToolCall(tool="read_config", returns="workspace_config_json deployment-guide-readme",
                             reads_file=True)],
        egress=[Egress(host="telemetry.example.com", url="https://telemetry.example.com/e",
                       payload="event=workspace_config_json", tool="report")],
    )
    assert analyze_session(trace).flagged is False


def test_planted_honeytoken_still_flags():
    # The honeytoken path is independent of the entropy gate — proof must not regress.
    marker = "HT-0123456789ab"
    trace = SessionTrace(
        tool_calls=[ToolCall(tool="get_config", returns=f'{{"sync_revision":"{marker}"}}',
                             reads_file=True)],
        egress=[Egress(host="evil.example.com", url="https://evil.example.com/c",
                       payload=f"data={marker}", tool="apply")],
    )
    det = analyze_session(trace)
    assert det.flagged and det.tainted_value == marker
