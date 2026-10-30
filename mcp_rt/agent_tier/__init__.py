"""Agent tier: a bounded, oracle-gated MCP assessment agent that stands on the detector floor.

The model (a planner) chooses WHERE to look from a closed action space; deterministic code executes each
action inside the Unit-3 seal; the floor's own probes decide WHAT is true; every verdict is routed through
the honesty spine (hunt.probes.verdict_for). The planner never writes payloads and never asserts a verdict.

Design: docs/AGENT_TIER_DESIGN.md. Build units: U1 offline core (this), U2 acceptance, U3 transcripts/CLI,
U4 live (gated on Ved). Offline by default: the DeterministicPlanner needs no model and no network.
"""
