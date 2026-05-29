"""MCP server exposing read-only System Cleaner tools."""

from __future__ import annotations

import json
from pathlib import Path

from syscleaner.plan_builder import build_plan_from_bundle
from syscleaner.scan_bundle import load_scan_bundle

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "MCP extra not installed. Run: uv sync --extra mcp",
    ) from exc

mcp = FastMCP("syscleaner")


def _load(path: str) -> dict:
    with Path(path).expanduser().open(encoding="utf-8") as f:
        return json.load(f)


@mcp.tool()
def health() -> str:
    """Return tool version and readiness."""
    from syscleaner import __version__

    return json.dumps({"status": "ok", "version": __version__})


@mcp.tool()
def scan_summary(scan_json_path: str) -> str:
    """Summarize a saved scan JSON (findings count, reclaimable estimate)."""
    bundle = load_scan_bundle(_load(scan_json_path))
    total_bytes = sum(f.size_bytes for f in bundle.findings)
    return json.dumps(
        {
            "platform": bundle.platform,
            "findings": len(bundle.findings),
            "security_issues": len(bundle.security_issues),
            "reclaimable_gb": round(total_bytes / (1024**3), 2),
        },
        indent=2,
    )


@mcp.tool()
def export_plan(scan_json_path: str, tier: str = "moderate") -> str:
    """Build cleanup plan JSON from a saved scan."""
    from syscleaner.models.entities import RiskTier

    bundle = load_scan_bundle(_load(scan_json_path))
    plan = build_plan_from_bundle(bundle, max_risk=RiskTier(tier))
    return plan.model_dump_json(indent=2)


def main() -> None:
    """Run MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
