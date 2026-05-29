"""MCP tool logic tests (no stdio server)."""

import json
from pathlib import Path

from syscleaner.mcp_server import export_plan, scan_summary

FIXTURE = Path(__file__).parent / "fixtures" / "scan_sample.json"


def test_scan_summary_tool() -> None:
    raw = scan_summary(str(FIXTURE))
    data = json.loads(raw)
    assert data["findings"] == 2
    assert data["security_issues"] == 1


def test_export_plan_tool() -> None:
    raw = export_plan(str(FIXTURE), tier="safe")
    data = json.loads(raw)
    assert "actions" in data
