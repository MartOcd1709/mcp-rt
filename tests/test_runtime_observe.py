"""Unit 3 pure logic: token forms, inspectability, and every verdict row. No namespace and no server here."""
import base64
from pathlib import Path

from hunt.probes import CLEAN, INCONCLUSIVE, SUSPECTED, VULNERABLE, verdict_for
from mcp_rt.runtime import observe
from mcp_rt.runtime.sandbox import has_ipv6_attempt, strace_destinations

TOKEN = "HT-0123456789abcdef"
REPO = Path(__file__).resolve().parents[1]
CORPUS_NAMES = ["egress_evasion", "elicitation_prompt", "proxy_aggregator", "resource_content",
                "server_side_workflow", "tool_annotation", "tool_description_injection",
                "benign_invoice", "benign_routing", "benign_update_check"]


def ev(payload, *, dst="1.1.1.1", port=80, proto="tcp", truncated=False):
    return {"proto": proto, "dst": dst, "port": port, "truncated": truncated, "phase": "server",
            "payload": base64.b64encode(payload).decode()}


def witness(*pairs):
    return "\n".join(f'connect(3, {{sa_family=AF_INET, sin_port=htons({p}), sin_addr=inet_addr("{ip}")}}, 16) = 0'
                     for ip, p in pairs)


_AUTO = object()


def v(events, *, sealed=True, started=True, text=_AUTO, claim="", token=TOKEN, refused_calls=()):
    if text is _AUTO:  # an explicit None means "the witness is missing", so it must reach the verdict as None
        text = witness(*{(e["dst"], e["port"]) for e in events}) if events else ""
    return observe.verdict(sealed=sealed, server_started=started, events=events, strace_text=text,
                           token=token, claim_text=claim, refused_calls=refused_calls)


def test_raw_hex_and_base64_forms_count_and_other_tokens_do_not():
    assert observe.token_hits(b"x " + TOKEN.encode(), TOKEN) == ["raw"]
    assert "hex" in observe.token_hits(TOKEN.encode().hex().encode(), TOKEN)
    shifted = b"prefix!" + base64.b64encode(b"zz" + TOKEN.encode() + b"zz")  # the token at another base64 phase
    assert "base64" in observe.token_hits(shifted, TOKEN)
    assert observe.token_hits(b"HT-ffffffffffffffff and HT-0000000000000000", TOKEN) == []


def test_tls_record_is_opaque_and_plain_text_is_inspectable():
    tls = bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + bytes(range(200, 232))
    assert not observe.inspectable(tls, False, 443)
    assert observe.inspectable(b'POST /collect HTTP/1.1\r\nHost: x\r\n\r\n{"v": 1}', False, 9999)


def test_binary_is_opaque_truncated_is_not_inspectable_and_dns_is_plain():
    assert not observe.inspectable(bytes(range(128, 256)) * 4, False, 9999)
    assert not observe.inspectable(b"plain text", True, 80)
    assert observe.inspectable(b"\x12\x34\x01\x00 dns-like", False, 53)
    assert observe.inspectable(b"", False, 80)


def test_unproven_seal_or_missing_server_never_clears_anything():
    for kwargs in ({"sealed": False}, {"started": False}):
        r = v([], **kwargs)
        assert r["method"] == "sandbox_unproven" and r["verdict"] == INCONCLUSIVE


def test_unobservable_when_witness_missing_ipv6_or_disagreeing():
    assert v([], text=None)["method"] == "sandbox_unobservable"
    assert v([], text='connect(3, {sa_family=AF_INET6, sin6_port=htons(80)}, 28) = 0')["method"] == "sandbox_unobservable"
    assert v([ev(b"hello")], text=witness(("9.9.9.9", 443)))["method"] == "sandbox_unobservable"


def test_marker_observed_wins_over_claim_and_explained_egress():
    r = v([ev(f'{{"v": "{TOKEN}"}}'.encode())], claim="Checks for updates. Makes no external calls.")
    assert r["method"] == "oracle" and r["verdict"] == VULNERABLE


def test_encoded_marker_observed_is_vulnerable():
    r = v([ev(base64.b64encode(TOKEN.encode()))], claim="Checks for updates from the remote service.")
    assert r["verdict"] == VULNERABLE


def test_no_egress_is_clean():
    r = v([])
    assert r["method"] == "sandbox_no_egress" and r["verdict"] == CLEAN


def test_claim_mismatch_is_suspected_not_clean():
    r = v([ev(b'{"event": "ping"}')], claim="Runs locally. Makes no external calls.")
    assert r["method"] == "sandbox_claim_mismatch" and r["verdict"] == SUSPECTED


def test_unexplained_egress_is_suspected():
    assert v([ev(b'{"event": "ping"}')], claim="Summarize the invoice.")["method"] == "sandbox_unexplained_egress"


def test_explained_egress_with_inspected_payload_is_clean():
    r = v([ev(b'{"event": "ping"}')], claim="Checks for updates against the remote service.")
    assert r["method"] == "sandbox_explained_egress" and r["verdict"] == CLEAN


def test_opaque_payload_is_never_clean():
    opaque = ev(bytes(range(128, 256)) * 4, port=9999)
    r = v([opaque], claim="Checks for updates from the remote service.")
    assert r["method"] == "sandbox_opaque_payload" and r["verdict"] == INCONCLUSIVE
    assert v([opaque], claim="Summarize the invoice.")["method"] == "sandbox_unexplained_egress"
    assert v([opaque], claim="Makes no external calls.")["verdict"] == SUSPECTED


def test_other_tokens_do_not_clear_or_flag():
    r = v([ev(b'{"token": "HT-ffffffffffffffff"}')], claim="Checks for updates from the remote service.")
    assert r["verdict"] == CLEAN


def test_every_method_resolves_through_the_verdict_spine():
    expected = {
        "sandbox_claim_mismatch": SUSPECTED,
        "sandbox_unexplained_egress": SUSPECTED, "sandbox_explained_egress": CLEAN,
        "sandbox_no_egress": CLEAN, "sandbox_opaque_payload": INCONCLUSIVE,
        "sandbox_unproven": INCONCLUSIVE, "sandbox_unobservable": INCONCLUSIVE,
        "sandbox_not_exercised": INCONCLUSIVE,
    }
    assert {m: verdict_for(m) for m in expected} == expected


def test_silence_after_a_refused_input_is_not_clean():
    r = v([], claim="Route a request to a tool on the workspace.", refused_calls=("gateway_call",))
    assert r["method"] == "sandbox_not_exercised" and r["verdict"] == INCONCLUSIVE
    assert v([], refused_calls=())["method"] == "sandbox_no_egress"
    assert observe.REFUSAL.match("error: unknown downstream tool 'x'")
    assert not observe.REFUSAL.match('{"current": "1.4.2", "latest": "1.4.3"}')


def test_strace_destinations_and_ipv6_attempts():
    text = witness(("1.1.1.1", 80), ("127.0.0.1", 9999)) + '\nconnect(4, {sa_family=AF_INET6, sin6_port=htons(80)}, 28) = 0'
    assert strace_destinations(text) == {("1.1.1.1", 80), ("127.0.0.1", 9999)}
    assert has_ipv6_attempt(text)
    assert not has_ipv6_attempt("socket(AF_INET6, SOCK_STREAM, IPPROTO_IP) = 5")  # creating a socket is not an attempt


def test_local_names_and_pid_prefixes_do_not_invent_attempts():
    text = ('42 getsockname(7, {sa_family=AF_INET, sin_port=htons(42832), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0\n'
            '42 connect(7, {sa_family=AF_INET, sin_port=htons(9999), sin_addr=inet_addr("127.0.0.1")}, 16) = -1\n'
            '43 accept4(5, {sa_family=AF_INET, sin_port=htons(55555), sin_addr=inet_addr("10.0.0.9")}, [16], 0) = 6')
    assert strace_destinations(text) == {("127.0.0.1", 9999)}
    assert not has_ipv6_attempt('42 getsockname(7, {sa_family=AF_INET6, sin6_port=htons(1)}, [28]) = 0')
    assert has_ipv6_attempt('42 connect(4, {sa_family=AF_INET6, sin6_port=htons(443)}, 28) = 0')


def test_runtime_code_is_name_free():
    source = "".join(p.read_text() for p in (REPO / "mcp_rt" / "runtime").glob("*.py"))
    assert not [name for name in CORPUS_NAMES if name in source]
