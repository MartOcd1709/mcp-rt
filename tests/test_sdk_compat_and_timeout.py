"""Regression guards for the REA-hardening fixes:
  #1 SDK-agnostic tool-schema access (mcp 1.x `inputSchema` vs 2.x `input_schema`)
  #2 per-call timeout so one hanging tool can't wedge the whole scan
"""
import asyncio

import pytest

from hunt.probes import _schema, _guard_call_tool, _CALL_TIMEOUT_S


class _Tool:
    def __init__(self, **kw):  # mimic either SDK's Tool attribute shape
        self.__dict__.update(kw)


def test_schema_reads_new_sdk_field():
    assert _schema(_Tool(input_schema={"properties": {"a": {}}})) == {"properties": {"a": {}}}


def test_schema_reads_old_sdk_field():
    assert _schema(_Tool(inputSchema={"properties": {"b": {}}})) == {"properties": {"b": {}}}


def test_schema_missing_is_empty_dict():
    assert _schema(_Tool()) == {}
    assert _schema(_Tool(input_schema=None, inputSchema=None)) == {}


def test_default_call_timeout_is_finite():
    assert _CALL_TIMEOUT_S > 0  # a hang must always be bounded


def test_guard_call_tool_bounds_a_hanging_call():
    class _Session:
        async def call_tool(self, *_a, **_k):
            await asyncio.sleep(3600)  # never returns

    s = _Session()
    _guard_call_tool(s, timeout=0.05)
    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        asyncio.run(s.call_tool("x", {}))
