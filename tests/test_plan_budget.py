"""Plan builder budget and trash action tests."""

from syscleaner.models.entities import ActionType, Finding, RiskTier, ScanBundle
from syscleaner.plan_builder import (
    build_plan_from_bundle,
    finding_to_action,
    legacy_cleanup_to_findings,
)


def test_plan_target_gb_stops_early() -> None:
    findings = [
        Finding(
            id=f"f{i}",
            recognizer_id="uv_cache",
            category="python",
            title=f"cache {i}",
            size_bytes=1024**3,
            risk=RiskTier.SAFE,
            metadata={"cli_available": False},
        )
        for i in range(5)
    ]
    bundle = ScanBundle(findings=findings)
    plan = build_plan_from_bundle(bundle, max_risk=RiskTier.SAFE, target_bytes=2 * 1024**3)
    assert len(plan.actions) <= 3


def test_plan_includes_trash_action() -> None:
    bundle = ScanBundle(
        findings=[],
        scan_results={
            "trash": {
                "path": "/home/user/.Trash",
                "size_mb": 100.0,
                "size_bytes": 100 * 1024 * 1024,
            },
        },
    )
    plan = build_plan_from_bundle(bundle, max_risk=RiskTier.SAFE)
    assert any(a.title == "Empty trash" for a in plan.actions)


def test_legacy_cleanup_to_findings() -> None:
    findings = legacy_cleanup_to_findings(
        {
            "recommendations": [
                {
                    "type": "cache",
                    "path": "/tmp/x",
                    "size_mb": 10,
                    "description": "temp",
                },
            ],
        },
    )
    assert len(findings) == 1
    assert findings[0].recognizer_id == "legacy_cleanup"


def test_finding_to_action_manual_when_no_cli() -> None:
    finding = Finding(
        id="1",
        recognizer_id="uv_cache",
        category="python",
        title="uv",
        risk=RiskTier.SAFE,
        metadata={},
    )
    action = finding_to_action(finding, cli_available=False)
    assert action.action_type == ActionType.MANUAL


def test_finding_to_action_delete_moderate_path() -> None:
    finding = Finding(
        id="2",
        recognizer_id="custom",
        category="other",
        title="big dir",
        path="/tmp/big",
        risk=RiskTier.MODERATE,
    )
    action = finding_to_action(finding, cli_available=True)
    assert action.action_type == ActionType.DELETE_PATH
