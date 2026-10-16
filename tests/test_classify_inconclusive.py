"""Honest INCONCLUSIVE classification: every failure reason gets a real category, and
'never ran' (SETUP_FAILED) is kept OUT of the verdict-reliability denominator — not hidden,
not counted as 'we couldn't test a working server'. Locks the buckets so they can't regress
to an opaque 'OTHER' blob (which made 52% of runs look inconclusive when most just needed
credentials, config, or had broken deps)."""
from hunt.sweep import _classify, _verdict_for

# (reason text seen in a scan note) -> expected category
_CASES = {
    # needs credentials / config -> SETUP_FAILED (target can't run without operator input)
    "Missing required environment variable GITHUB_TOKEN": "NEEDS_CONFIG",
    "please specify a model with --model or set a default model": "NEEDS_CONFIG",
    "error: no connection string. pass it as an argument": "NEEDS_CONFIG",
    "环境变量 V_MOO_PASSWORD 未设置": "NEEDS_CONFIG",
    "clicbase_api_key manquante": "NEEDS_CONFIG",
    # entrypoint / launch resolution -> SETUP_FAILED
    "The following executables are available: foo, bar": "ENTRYPOINT_NOT_FOUND",
    "code: 'ENOENT'": "ENTRYPOINT_NOT_FOUND",
    # broken/incompatible package -> SETUP_FAILED
    "ModuleNotFoundError: No module named 'mcp.server.fastmcp'": "BROKEN_PACKAGE",
    "SyntaxError: Unexpected token": "BROKEN_PACKAGE",
    "sh: 1: syntax error: word unexpected": "BROKEN_PACKAGE",
    "invalid command: stdio": "BROKEN_PACKAGE",
    # install -> SETUP_FAILED
    "npm ERR! 404 Not Found": "INSTALL_FAILED",
    # ran but no verdict -> stays INCONCLUSIVE
    "ExceptionGroup: unhandled errors in a TaskGroup (1 sub-exception)": "PROTOCOL_ERROR",
    "could not probe: ExceptionGroup": "PROTOCOL_ERROR",
    "code: 'ERR_INVALID_URL'": "PROTOCOL_ERROR",
    "scan exceeded 90s (server started but slow": "SCAN_TIMEOUT",
}

_SETUP = {"NEEDS_CONFIG", "ENTRYPOINT_NOT_FOUND", "BROKEN_PACKAGE", "INSTALL_FAILED", "NEEDS_SUBCOMMAND"}
_RAN = {"PROTOCOL_ERROR", "SCAN_TIMEOUT", "OTHER"}


def test_each_reason_classifies_as_expected():
    for reason, want in _CASES.items():
        got = _classify(reason)
        assert got == want, f"{reason!r}: got {got}, want {want}"


def test_setup_fail_categories_leave_the_inconclusive_denominator():
    for cat in _SETUP:
        assert _verdict_for(cat) == "SETUP_FAILED", cat


def test_ran_but_no_verdict_stays_inconclusive():
    for cat in _RAN:
        assert _verdict_for(cat) == "INCONCLUSIVE", cat


def test_unknown_reason_is_other_not_crash():
    assert _classify("something totally novel with no keywords") == "OTHER"
    assert _verdict_for("OTHER") == "INCONCLUSIVE"   # opaque -> honest inconclusive, never hidden
