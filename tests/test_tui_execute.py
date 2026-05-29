"""TUI execute helper tests (no full Textual UI)."""

from syscleaner.apply.orchestrator import apply_plan
from syscleaner.models.entities import Action, ActionType, CleanupPlan, RiskTier
from syscleaner.tui_app import execute_safe_plan


def test_execute_safe_plan_dry_run_manual_only() -> None:
    plan = CleanupPlan(
        actions=[
            Action(
                id="1",
                finding_id="f1",
                action_type=ActionType.MANUAL,
                title="manual",
                risk=RiskTier.SAFE,
                manual_reason="do by hand",
            ),
        ],
    )
    result = execute_safe_plan(plan)
    assert result.dry_run is False
    assert result.skipped == 1


def test_execute_safe_matches_apply_flags() -> None:
    plan = CleanupPlan(
        actions=[
            Action(
                id="1",
                finding_id="f1",
                action_type=ActionType.NATIVE_CLI,
                title="uv",
                risk=RiskTier.SAFE,
                command=["nonexistent-binary-xyz"],
            ),
        ],
    )
    direct = apply_plan(
        plan,
        dry_run=False,
        max_risk=RiskTier.SAFE,
        allow_risky=False,
        yes=True,
    )
    via_tui = execute_safe_plan(plan)
    assert direct.failed == via_tui.failed
