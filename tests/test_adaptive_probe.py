"""Adaptive probe generation: offline model selection + the ground-truth contract.

Generation only — a candidate is NOT a finding until its canary fires in the sandboxed executor.
Tests run with the mock (offline) model; no API key needed.
"""
from mcp_rt import adaptive_probe as ap


def _clear(monkeypatch):
    for k in ("MCPRT_AI_PROVIDER", "MCPRT_AI_MODEL", "MCPRT_AI_BASE_URL", "MCPRT_AI_API_KEY",
              "ANTHROPIC_API_KEY", "MCPRT_AI_MODEL_NAME"):
        monkeypatch.delenv(k, raising=False)


def test_get_model_defaults_to_mock(monkeypatch):
    _clear(monkeypatch)
    assert ap.get_model().name == "mock"


def test_openai_provider_selected_for_csi(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MCPRT_AI_PROVIDER", "openai")
    monkeypatch.setenv("MCPRT_AI_BASE_URL", "https://api.aliasrobotics.com/v1")
    monkeypatch.setenv("MCPRT_AI_API_KEY", "csi-test")
    monkeypatch.setenv("MCPRT_AI_MODEL_NAME", "alias3")
    m = ap.get_model()
    assert m.name == "openai" and m.model == "alias3" and m.base_url.endswith("/v1")


def test_anthropic_provider_selected(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MCPRT_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert ap.get_model().name == "anthropic"


def test_incomplete_openai_config_falls_back_to_mock(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MCPRT_AI_PROVIDER", "openai")   # base_url/key missing -> mock
    assert ap.get_model().name == "mock"


def test_generate_candidates_targets_real_tools():
    tools = ["get_weather", "read_file", "run_query"]
    cands = ap.generate_candidates(tools, n=6)
    assert 1 <= len(cands) <= 6
    for c in cands:
        assert c.target_tool in tools           # each probe is aimed at an actual target tool
        assert c.technique                        # drawn from our known detection corpus
        assert c.source == "mock"


def test_candidates_draw_from_known_corpus():
    known = {t["technique"] for t in ap._known_techniques()}
    assert len(known) >= 30                       # the registered payload corpus
    cands = ap.generate_candidates(["x"], n=5)
    assert all(c.technique in known for c in cands)   # adapts KNOWN techniques, not invented ones


def test_model_failure_degrades_to_offline(monkeypatch):
    class Boom(ap.ProbeModel):
        name = "boom"
        def propose(self, *a, **k):
            raise RuntimeError("model down")
    cands = ap.generate_candidates(["t"], n=3, model=Boom())
    assert cands and all(c.source == "mock" for c in cands)   # never crashes; falls back
