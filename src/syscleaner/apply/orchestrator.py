"""Execute cleanup plans with dry-run and risk gates."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from syscleaner.models.entities import Action, ActionType, CleanupPlan, RiskTier

logger = logging.getLogger(__name__)


@dataclass
class ApplyResult:
    """Summary of apply execution."""

    executed: int = 0
    skipped: int = 0
    failed: int = 0
    dry_run: bool = True
    messages: list[str] = field(default_factory=list)


def _tier_allowed(action: Action, max_risk: RiskTier, allow_risky: bool) -> bool:
    order = {RiskTier.SAFE: 0, RiskTier.MODERATE: 1, RiskTier.RISKY: 2}
    if action.risk == RiskTier.RISKY and not allow_risky:
        return False
    return order[action.risk] <= order[max_risk]


def apply_plan(
    plan: CleanupPlan,
    *,
    dry_run: bool = True,
    max_risk: RiskTier = RiskTier.MODERATE,
    allow_risky: bool = False,
    yes: bool = False,
) -> ApplyResult:
    """Run plan actions respecting risk tier and dry-run mode."""
    result = ApplyResult(dry_run=dry_run)

    for action in plan.actions:
        if not _tier_allowed(action, max_risk, allow_risky):
            result.skipped += 1
            result.messages.append(f"SKIP (tier): {action.title}")
            continue

        if action.action_type == ActionType.MANUAL:
            result.skipped += 1
            result.messages.append(f"MANUAL: {action.title} — {action.manual_reason}")
            continue

        if dry_run:
            result.executed += 1
            result.messages.append(_describe_dry_run(action))
            continue

        if action.requires_confirm and not yes:
            result.skipped += 1
            result.messages.append(f"SKIP (no --yes): {action.title}")
            continue

        try:
            _execute_action(action)
            result.executed += 1
            result.messages.append(f"OK: {action.title}")
        except Exception as e:
            result.failed += 1
            logger.error("Apply failed for %s: %s", action.title, e)
            result.messages.append(f"FAIL: {action.title} — {e}")

    return result


def _describe_dry_run(action: Action) -> str:
    if action.action_type == ActionType.NATIVE_CLI:
        return f"DRY-RUN CLI: {' '.join(action.command)}"
    if action.action_type == ActionType.DELETE_PATH:
        return f"DRY-RUN DELETE: {action.path}"
    if action.action_type == ActionType.EMPTY_TRASH:
        return f"DRY-RUN EMPTY TRASH: {action.path or '~/.Trash'}"
    return f"DRY-RUN: {action.title}"


def _execute_action(action: Action) -> None:
    if action.action_type == ActionType.NATIVE_CLI:
        if not action.command:
            raise ValueError("Empty command")
        bin_name = action.command[0]
        if not shutil.which(bin_name):
            raise FileNotFoundError(f"Binary not found: {bin_name}")
        subprocess.run(action.command, check=True, capture_output=True, text=True)
        return

    if action.action_type == ActionType.DELETE_PATH:
        if not action.path:
            raise ValueError("Missing path")
        target = Path(action.path).expanduser()
        if not target.exists():
            logger.warning("Path already gone: %s", target)
            return
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        return

    if action.action_type == ActionType.EMPTY_TRASH:
        trash = Path(action.path).expanduser() if action.path else Path.home() / ".Trash"
        if not trash.exists():
            return
        for child in trash.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        return

    raise ValueError(f"Unsupported action type: {action.action_type}")
