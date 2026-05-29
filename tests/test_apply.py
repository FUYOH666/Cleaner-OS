"""Apply orchestrator tests."""

from syscleaner.apply.orchestrator import apply_plan
from syscleaner.models.entities import Action, ActionType, CleanupPlan, RiskTier


def test_apply_dry_run() -> None:
    plan = CleanupPlan(
        actions=[
            Action(
                id="1",
                finding_id="f1",
                action_type=ActionType.NATIVE_CLI,
                title="uv prune",
                risk=RiskTier.SAFE,
                command=["uv", "cache", "prune"],
            ),
            Action(
                id="2",
                finding_id="f2",
                action_type=ActionType.DELETE_PATH,
                title="temp",
                risk=RiskTier.RISKY,
                path="/tmp/should-not-delete",
            ),
        ],
    )
    result = apply_plan(plan, dry_run=True, max_risk=RiskTier.SAFE, allow_risky=False)
    assert result.dry_run is True
    assert result.executed == 1
    assert result.skipped == 1
    assert any("DRY-RUN CLI" in m for m in result.messages)


def test_apply_skips_manual() -> None:
    plan = CleanupPlan(
        actions=[
            Action(
                id="1",
                finding_id="f1",
                action_type=ActionType.MANUAL,
                title="manual step",
                risk=RiskTier.MODERATE,
                manual_reason="Install hf CLI",
            ),
        ],
    )
    result = apply_plan(plan, dry_run=False, max_risk=RiskTier.MODERATE, yes=True)
    assert result.skipped == 1
