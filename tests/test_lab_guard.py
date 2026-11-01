"""R3 quarantine: the pre-seal modes (`agent`, `pentest`) refuse a non-lab target.

These modes run the target unsandboxed on the host with model-chosen arguments. Until they are rebuilt on
the Unit 3 seal, only in-repo lab fixtures are allowed by default. The CLI must refuse anything else before
it spawns the target, and the refusal must not depend on a real model or network.
"""
from pathlib import Path

import pytest

from mcp_rt import agent_loop, assessment
from mcp_rt.lab_guard import OVERRIDE_ENV, UnsandboxedTargetRefused, is_lab_target, require_lab_target

REPO = Path(__file__).resolve().parents[1]
LAB = f"python3 {REPO / 'fixtures' / 'proxy_aggregator' / 'server.py'}"
PROBE_FIXTURE = f"python3 {REPO / 'hunt' / 'probe_fixtures' / 'vuln_server.py'}"
NON_LAB = "python3 /tmp/some_other_server.py"


def test_lab_fixture_paths_are_recognised():
    assert is_lab_target(LAB)
    assert is_lab_target(PROBE_FIXTURE)


def test_non_lab_and_module_targets_are_not_lab():
    assert not is_lab_target(NON_LAB)
    assert not is_lab_target("python3 -m some.module")
    assert not is_lab_target("")


def test_require_refuses_non_lab_target(monkeypatch):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    with pytest.raises(UnsandboxedTargetRefused):
        require_lab_target(NON_LAB, mode="agent")


def test_require_allows_lab_target(monkeypatch):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    require_lab_target(LAB, mode="agent")   # does not raise


def test_override_env_allows_non_lab(monkeypatch):
    monkeypatch.setenv(OVERRIDE_ENV, "1")
    require_lab_target(NON_LAB, mode="pentest")   # deliberate opt-in, does not raise


def test_agent_cli_refuses_non_lab_before_spawning(monkeypatch, capsys):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    # If the guard let this through it would try to spawn /tmp/... ; a clean exit 2 proves it stopped first.
    rc = agent_loop.main(["--target-stdio", NON_LAB])
    assert rc == 2
    assert "refusing" in capsys.readouterr().err.lower()


def test_pentest_cli_refuses_non_lab_before_spawning(monkeypatch, capsys):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    rc = assessment.main(["--target-stdio", NON_LAB])
    assert rc == 2
    assert "refusing" in capsys.readouterr().err.lower()
