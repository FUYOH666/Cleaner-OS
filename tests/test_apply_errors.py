"""Apply orchestrator error-path tests."""

from syscleaner.apply.orchestrator import apply_plan
from syscleaner.models.entities import Action, ActionType, CleanupPlan, RiskTier


def test_apply_requires_yes_for_execute() -> None:
    plan = CleanupPlan(
        actions=[
            Action(
                id="1",
                finding_id="f1",
                action_type=ActionType.DELETE_PATH,
                title="delete",
                risk=RiskTier.SAFE,
                path="/nonexistent/path",
                requires_confirm=True,
            ),
        ],
    )
    result = apply_plan(plan, dry_run=False, max_risk=RiskTier.SAFE, yes=False)
    assert result.skipped == 1


def test_apply_missing_binary_fails() -> None:
    plan = CleanupPlan(
        actions=[
            Action(
                id="1",
                finding_id="f1",
                action_type=ActionType.NATIVE_CLI,
                title="missing",
                risk=RiskTier.SAFE,
                command=["definitely-not-a-real-binary-xyz"],
            ),
        ],
    )
    result = apply_plan(plan, dry_run=False, max_risk=RiskTier.SAFE, yes=True)
    assert result.failed == 1


def test_apply_blocks_risky_without_flag() -> None:
    plan = CleanupPlan(
        actions=[
            Action(
                id="1",
                finding_id="f1",
                action_type=ActionType.DELETE_PATH,
                title="risky",
                risk=RiskTier.RISKY,
                path="/tmp/x",
            ),
        ],
    )
    result = apply_plan(plan, dry_run=True, max_risk=RiskTier.MODERATE, allow_risky=False)
    assert result.skipped == 1
