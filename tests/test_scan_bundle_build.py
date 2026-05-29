"""Scan bundle assembly tests."""

from unittest.mock import patch

from syscleaner.config import Settings
from syscleaner.models.entities import Finding, RiskTier
from syscleaner.platform.paths import PlatformPaths
from syscleaner.scan_bundle import build_scan_bundle


@patch("syscleaner.scan_bundle.run_recognizers")
def test_build_scan_bundle_merges_findings(mock_run, tmp_path) -> None:
    mock_run.return_value = [
        Finding(
            id="x",
            recognizer_id="uv_cache",
            category="python",
            title="uv",
            size_bytes=1000,
            risk=RiskTier.SAFE,
        ),
    ]
    paths = PlatformPaths(home=tmp_path)
    settings = Settings()
    bundle = build_scan_bundle(
        scan_results={"caches": [{"path": "/tmp", "size_mb": 1.0}]},
        security_results={"issues": [], "high_severity_issues": 0},
        cleanup_analysis={},
        ml_cache_results=None,
        dependency_results=None,
        paths=paths,
        settings=settings,
    )
    assert len(bundle.findings) >= 1
    assert bundle.schema_version == "1.0"
