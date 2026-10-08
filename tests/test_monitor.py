"""M4: continuous monitor — alert iff a re-test introduces a NEW finding; version re-pinned to latest."""
from hunt.monitor import _relatest, to_alert


def test_relatest_repins_version_only():
    assert _relatest("npx -y pkg@1.2.3") == "npx -y pkg@latest"
    assert _relatest("uvx pkg@0.5.0 /tmp/fs_allowed") == "uvx pkg@latest /tmp/fs_allowed"
    # scoped name: only the trailing version flips, @scope/ is untouched
    assert _relatest("npx -y @scope/pkg@1.0.0") == "npx -y @scope/pkg@latest"
    # unversioned stays as-is
    assert _relatest("npx -y pkg") == "npx -y pkg"


def test_alert_only_on_new_finding():
    when = "2026-10-06T00:00:00"
    # a newly-introduced class -> alert
    a = to_alert("pkg", prior={"sql_injection"}, current={"sql_injection", "command_injection"}, when=when)
    assert a is not None and a["new"] == ["command_injection"] and a["unchanged"] == ["sql_injection"]
    # only resolved / unchanged -> NO alert (a fix or steady state is not an alert)
    assert to_alert("pkg", prior={"sql_injection"}, current=set(), when=when) is None       # resolved
    assert to_alert("pkg", prior={"sql_injection"}, current={"sql_injection"}, when=when) is None
    assert to_alert("pkg", prior=set(), current=set(), when=when) is None                    # clean->clean
