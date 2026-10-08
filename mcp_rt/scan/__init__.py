"""Scan orchestration: drive a real MCP client against a target and read the verdict."""
from .runner import ScanResult, scan, verdict_from_capture

__all__ = ["ScanResult", "scan", "verdict_from_capture"]
