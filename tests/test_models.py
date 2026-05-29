"""Tests for Pydantic models and scan bundle."""

import json

from syscleaner.models.entities import (
    ActionType,
    Finding,
    RiskTier,
    ScanBundle,
    SecurityIssue,
)
from syscleaner.plan_builder import build_plan_from_bundle, legacy_cleanup_to_findings
from syscleaner.scan_bundle import load_scan_bundle


def test_finding_model() -> None:
    f = Finding(
        id="uv_cache:~/.cache/uv",
        recognizer_id="uv_cache",
        category="python",
        title="uv cache",
        path="/tmp/uv",
        size_bytes=1024,
        risk=RiskTier.SAFE,
    )
    assert f.risk == RiskTier.SAFE
    data = json.loads(f.model_dump_json())
    assert data["recognizer_id"] == "uv_cache"


def test_scan_bundle_roundtrip() -> None:
    bundle = ScanBundle(
        platform="macOS test",
        findings=[
            Finding(
                id="1",
                recognizer_id="uv_cache",
                category="python",
                title="uv",
                size_bytes=5000,
                risk=RiskTier.SAFE,
                metadata={"cli_available": True},
            ),
        ],
        security_issues=[
            SecurityIssue(
                path="/home/u/.ssh/id_rsa",
                category="ssh_permissions",
                severity="high",
                description="Permissions too open",
            ),
        ],
    )
    restored = ScanBundle.model_validate_json(bundle.model_dump_json())
    assert len(restored.findings) == 1
    assert restored.security_issues[0].severity == "high"


def test_build_plan_dedupes_native_cli() -> None:
    bundle = ScanBundle(
        findings=[
            Finding(
                id="a",
                recognizer_id="uv_cache",
                category="python",
                title="uv 1",
                risk=RiskTier.SAFE,
                metadata={"cli_available": True},
            ),
            Finding(
                id="b",
                recognizer_id="uv_cache",
                category="python",
                title="uv 2",
                risk=RiskTier.SAFE,
                metadata={"cli_available": True},
            ),
        ],
    )
    plan = build_plan_from_bundle(bundle, max_risk=RiskTier.SAFE)
    cli_actions = [a for a in plan.actions if a.action_type == ActionType.NATIVE_CLI]
    assert len(cli_actions) == 1


def test_load_legacy_scan_format() -> None:
    legacy = {
        "scan_results": {"caches": []},
        "security_results": {"issues": [], "total_issues": 0},
        "cleanup_analysis": {
            "recommendations": [
                {
                    "type": "trash",
                    "path": "~/.Trash",
                    "size_mb": 10,
                    "description": "Empty trash",
                },
            ],
            "total_reclaimable_gb": 0.01,
        },
    }
    bundle = load_scan_bundle(legacy)
    assert bundle.schema_version == "1.0"
    assert len(legacy_cleanup_to_findings(legacy["cleanup_analysis"])) >= 1


def test_legacy_cleanup_to_findings() -> None:
    analysis = {
        "recommendations": [
            {"type": "cache", "path": "/tmp/x", "size_mb": 100, "description": "big cache"},
        ],
    }
    findings = legacy_cleanup_to_findings(analysis)
    assert findings[0].size_bytes == 100 * 1024 * 1024
