"""Report generation tests."""

from syscleaner.i18n import set_locale
from syscleaner.reporter import generate_json_report, generate_markdown_report


def test_markdown_report_en() -> None:
    set_locale("en")
    md = generate_markdown_report(
        scan_results={
            "caches": [{"path": "/tmp/cache", "size_mb": 100.0, "size_formatted": "100 MB"}],
            "orphaned_apps": [],
            "hidden_files": [],
        },
        security_results={"issues": [], "high_severity_issues": 0},
        cleanup_analysis={},
        ml_cache_results={
            "total_models": 2,
            "total_size_gb": 5.0,
            "unused_models_count": 1,
            "unused_size_gb": 2.0,
            "models_by_type": {"hf": [{"size_gb": 5.0}]},
            "models": [{"name": "m1", "size_gb": 3.0, "cache_type": "hf"}],
        },
        platform="test",
    )
    assert "System Cleaner" in md or "Audit" in md
    assert "ML" in md


def test_markdown_report_ru() -> None:
    set_locale("ru")
    md = generate_markdown_report(
        scan_results={"caches": [], "orphaned_apps": [], "hidden_files": []},
        security_results={"issues": []},
        cleanup_analysis={},
        platform="test",
    )
    assert "Отчёт" in md or "Сводка" in md


def test_json_report() -> None:
    data = generate_json_report(
        scan_results={"caches": []},
        security_results={},
        cleanup_analysis={},
    )
    assert "scan_results" in data
    import json

    parsed = json.loads(data)
    assert "timestamp" in parsed
