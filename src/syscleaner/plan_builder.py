"""Build cleanup plans from scan bundles."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from syscleaner.models.entities import (
    Action,
    ActionType,
    CleanupPlan,
    Finding,
    RiskTier,
    ScanBundle,
)

logger = logging.getLogger(__name__)

# Recognizer -> native CLI when binary is available
NATIVE_ACTIONS: dict[str, tuple[str, list[str], bool]] = {
    "uv_cache": ("uv", ["uv", "cache", "prune"], True),
    "hf_hub": ("hf", ["hf", "cache", "prune"], True),
    "homebrew_cache": ("brew", ["brew", "cleanup", "-s"], True),
    "npm_cache": ("npm", ["npm", "cache", "clean", "--force"], True),
    "docker_cache": ("docker", ["docker", "system", "prune", "-f"], True),
}


def _action_id() -> str:
    return uuid.uuid4().hex[:12]


def finding_to_action(finding: Finding, *, cli_available: bool) -> Action:
    """Map a finding to an executable action."""
    recognizer = finding.recognizer_id
    if recognizer in NATIVE_ACTIONS:
        bin_name, cmd, dry_ok = NATIVE_ACTIONS[recognizer]
        if cli_available:
            return Action(
                id=_action_id(),
                finding_id=finding.id,
                action_type=ActionType.NATIVE_CLI,
                title=finding.title,
                risk=finding.risk,
                command=list(cmd),
                requires_confirm=finding.risk != RiskTier.SAFE,
                dry_run_supported=dry_ok,
            )
        return Action(
            id=_action_id(),
            finding_id=finding.id,
            action_type=ActionType.MANUAL,
            title=finding.title,
            risk=finding.risk,
            manual_reason=f"Install `{bin_name}` or run: {' '.join(cmd)}",
            requires_confirm=True,
            dry_run_supported=False,
        )

    if finding.path and finding.risk == RiskTier.SAFE:
        return Action(
            id=_action_id(),
            finding_id=finding.id,
            action_type=ActionType.DELETE_PATH,
            title=finding.title,
            risk=finding.risk,
            path=finding.path,
            requires_confirm=True,
            dry_run_supported=True,
        )

    if finding.path:
        return Action(
            id=_action_id(),
            finding_id=finding.id,
            action_type=ActionType.DELETE_PATH,
            title=finding.title,
            risk=finding.risk,
            path=finding.path,
            requires_confirm=True,
            dry_run_supported=True,
        )

    return Action(
        id=_action_id(),
        finding_id=finding.id,
        action_type=ActionType.MANUAL,
        title=finding.title,
        risk=finding.risk,
        manual_reason=finding.description or "Review manually",
        requires_confirm=True,
        dry_run_supported=False,
    )


def build_plan_from_bundle(
    bundle: ScanBundle,
    *,
    max_risk: RiskTier = RiskTier.RISKY,
    target_bytes: int | None = None,
) -> CleanupPlan:
    """Create a cleanup plan from scan findings and legacy cleanup analysis."""
    risk_order = {RiskTier.SAFE: 0, RiskTier.MODERATE: 1, RiskTier.RISKY: 2}
    max_level = risk_order[max_risk]

    actions: list[Action] = []
    total_bytes = 0
    by_risk: dict[str, int] = {t.value: 0 for t in RiskTier}

    sorted_findings = sorted(bundle.findings, key=lambda f: f.size_bytes, reverse=True)
    seen_commands: set[str] = set()
    for finding in sorted_findings:
        if risk_order.get(finding.risk, 99) > max_level:
            continue
        cli_ok = finding.metadata.get("cli_available", True)
        action = finding_to_action(finding, cli_available=bool(cli_ok))
        if action.command:
            cmd_key = " ".join(action.command)
            if cmd_key in seen_commands:
                continue
            seen_commands.add(cmd_key)
        actions.append(action)
        total_bytes += finding.size_bytes
        by_risk[finding.risk.value] = by_risk.get(finding.risk.value, 0) + 1
        if target_bytes and total_bytes >= target_bytes:
            break

    # Legacy trash recommendation
    trash = bundle.scan_results.get("trash") or {}
    if trash.get("size_mb", 0) > 0 and risk_order[RiskTier.SAFE] <= max_level:
        actions.append(
            Action(
                id=_action_id(),
                finding_id="trash",
                action_type=ActionType.EMPTY_TRASH,
                title="Empty trash",
                risk=RiskTier.SAFE,
                path=trash.get("path"),
                requires_confirm=True,
                dry_run_supported=True,
            ),
        )
        total_bytes += int(trash.get("size_bytes", 0))

    return CleanupPlan(
        actions=actions,
        total_reclaimable_bytes=total_bytes,
        by_risk=by_risk,
    )


def legacy_cleanup_to_findings(cleanup_analysis: dict[str, Any]) -> list[Finding]:
    """Convert legacy cleanup recommendations to Finding list."""
    findings: list[Finding] = []
    for rec in cleanup_analysis.get("recommendations", []):
        size_mb = rec.get("size_mb") or rec.get("total_size_mb") or 0
        path = rec.get("path") or rec.get("pattern", "")
        findings.append(
            Finding(
                id=f"legacy:{rec.get('type')}:{path}",
                recognizer_id="legacy_cleanup",
                category=rec.get("type", "cleanup"),
                title=rec.get("description", "Cleanup item"),
                path=str(path) if path else None,
                size_bytes=int(size_mb * 1024 * 1024),
                risk=RiskTier.MODERATE if rec.get("type") == "project_artifact" else RiskTier.SAFE,
                description=rec.get("description", ""),
                metadata=rec,
            ),
        )
    return findings
