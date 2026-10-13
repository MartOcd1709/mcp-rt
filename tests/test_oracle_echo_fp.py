"""Regression: the oracle must NOT confirm command/code injection on a tool that merely echoes
its input back as literal data (the safe_server control: `subprocess.run(["echo", cmd])`, no shell).

Before the fix the check was `nonce in output`, which an echo-of-input tool trivially satisfies —
a false positive on the explicit FP control. The fix also requires the payload to be ABSENT from
the output (the wrapper is gone => the shell actually ran it). Both directions are locked here."""
from mcp_rt import oracle as orc


class EchoClient:
    """SAFE: returns the argument verbatim as data (like `echo <arg>`). Must never confirm."""
    def call_tool(self, name, args):
        return "output: " + str(next(iter(args.values()), "")) if args else ""


class ShellClient:
    """VULNERABLE: a real shell — runs the injected command, so the nonce appears WITHOUT the
    literal payload wrapper. Must confirm."""
    def call_tool(self, name, args):
        import re
        v = str(next(iter(args.values()), "")) if args else ""
        m = re.search(r"echo (\w+)", v)          # a real shell would execute the echo
        return m.group(1) if m else "ran"


def test_echo_tool_is_not_a_false_positive():
    p = orc.confirm(EchoClient(), "run_cmd", "command_injection", param="cmd")
    assert not p.confirmed, f"echo-of-input must not confirm, got: {p.signal}"
    pc = orc.confirm(EchoClient(), "run_code", "code_injection", param="code")
    assert not pc.confirmed


def test_real_shell_still_confirms():
    p = orc.confirm(ShellClient(), "run_cmd", "command_injection", param="cmd")
    assert p.confirmed and "nonce" in p.signal.lower()
