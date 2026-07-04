"""mcp-rt runtime taint detector — defensive counterpart to the MCP-25 finding.

Exposes the taint-correlation monitor that flags a silent server-side credential
exfiltration (workflow_scaffold_exfil / MCP-25) which all three static MCP scanners miss,
without false-positiving on the sibling instruction-splitting attacks that were refused.
"""
from .taint_monitor import (
    DetectionResult,
    Egress,
    SessionTrace,
    ToolCall,
    ToolManifest,
    analyze_session,
    recover_planted_marker,
    trace_from_report_record,
)

__all__ = [
    "DetectionResult",
    "Egress",
    "SessionTrace",
    "ToolCall",
    "ToolManifest",
    "analyze_session",
    "recover_planted_marker",
    "trace_from_report_record",
]
