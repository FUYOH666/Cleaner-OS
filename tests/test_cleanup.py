"""Cleanup analysis wrapper tests."""

from syscleaner.cleanup import analyze_cleanup_opportunities


def test_analyze_cleanup_from_caches() -> None:
    result = analyze_cleanup_opportunities(
        {
            "caches": [
                {
                    "path": "/tmp/big",
                    "name": "BigApp",
                    "size_mb": 100.0,
                    "size_formatted": "100 MB",
                },
            ],
        },
        ml_cache_results={"unused_size_gb": 2.0, "unused_models_count": 3},
    )
    assert result["total_reclaimable_gb"] > 0
    assert len(result["recommendations"]) >= 2


def test_analyze_cleanup_project_artifacts() -> None:
    result = analyze_cleanup_opportunities(
        {
            "project_artifacts": [
                {
                    "type": "node_modules",
                    "count": 5,
                    "total_size_mb": 500.0,
                    "total_size_formatted": "500 MB",
                },
            ],
        },
    )
    assert any(r["type"] == "project_artifact" for r in result["recommendations"])
