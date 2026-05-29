"""MCP apply tool gating."""

import json
from pathlib import Path

from syscleaner.mcp_server import apply_plan_tool

FIXTURE = Path(__file__).parent / "fixtures" / "scan_sample.json"


def test_apply_defaults_to_dry_run() -> None:
    raw = apply_plan_tool(str(FIXTURE), allow_execute=False)
    data = json.loads(raw)
    assert data["dry_run"] is True
