"""Which environment variables the sealed canary run replaces with canaries, and which it passes through as the
server's real configuration. Decided on the variable NAME, generically (no server-specific knowledge)."""
import tempfile

from mcp_rt.runtime.runner import build_sealed_launcher, operator_env, plant_canaries


def _plant(declared=(), passthrough=None):
    planted, env = plant_canaries(tempfile.mkdtemp(), "HT-x", declared_env=declared, passthrough=passthrough)
    return {p["where"] for p in planted if p["kind"] == "own_env"}, env


def test_credential_names_become_canaries_whether_declared_or_passed():
    own, env = _plant(("API_TOKEN",), {"JIRA_API_TOKEN": "real-secret"})
    assert own == {"API_TOKEN", "JIRA_API_TOKEN"}
    assert env["API_TOKEN"].startswith("HT-x-OWN") and env["JIRA_API_TOKEN"].startswith("HT-x-OWN")
    assert "real-secret" not in env.values()            # a real secret never enters the seal


def test_configuration_passes_through_as_the_operator_supplied_it():
    own, env = _plant(("ALLOW_COMMANDS",), {"ALLOW_COMMANDS": "ls,cat", "MODE": "prod"})
    assert not own
    assert env["ALLOW_COMMANDS"] == "ls,cat" and env["MODE"] == "prod"


def test_configuration_without_a_value_is_left_unset():
    own, env = _plant(("LOG_LEVEL", "ALLOW_COMMANDS"))
    assert not own and "LOG_LEVEL" not in env and "ALLOW_COMMANDS" not in env


def test_ambient_canaries_are_unaffected():
    _, env = _plant(("ALLOW_COMMANDS",), {"ALLOW_COMMANDS": "ls"})
    assert env["OPENAI_API_KEY"].endswith("-EOPENAI") and env["GITHUB_TOKEN"].endswith("-EGITHUB")


def test_operator_env_reads_only_the_named_variables():
    assert operator_env({"MCPRT_TARGET_ENV": "A, B ,C", "A": "1", "C": "3", "D": "4"}) == {"A": "1", "C": "3"}
    assert operator_env({}) == {}


def test_an_env_allowlist_launcher_is_told_to_let_them_through():
    params, paths = build_sealed_launcher(["true"], tempfile.mkdtemp(), "HT-y", declared_env=("API_TOKEN",),
                                          passthrough={"ALLOW_COMMANDS": "ls"})
    assert {"ALLOW_COMMANDS", "API_TOKEN", "OPENAI_API_KEY"} <= set(params.env["MCPRT_TARGET_ENV"].split(","))
    assert params.env["ALLOW_COMMANDS"] == "ls"
    assert paths["config_env"] == ["ALLOW_COMMANDS"]     # names only reach the record
