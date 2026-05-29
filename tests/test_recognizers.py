"""Recognizer plugin tests."""

from pathlib import Path

from syscleaner.config import Settings
from syscleaner.platform.paths import PlatformPaths
from syscleaner.recognizers.registry import run_recognizers


def test_uv_cache_recognizer(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cache = home / ".cache" / "uv"
    cache.mkdir(parents=True)
    (cache / "artifact").write_bytes(b"x" * 2048)

    paths = PlatformPaths(home=home)
    settings = Settings()
    settings.recognizers.enabled = ["uv_cache"]

    findings = run_recognizers(paths, settings)
    assert len(findings) == 1
    assert findings[0].recognizer_id == "uv_cache"
    assert findings[0].size_bytes >= 2048


def test_legacy_cache_recognizer(tmp_path: Path) -> None:
    home = tmp_path / "home"
    paths = PlatformPaths(home=home)
    settings = Settings()
    legacy = [{"path": str(home / "cache"), "size_mb": 15.0, "name": "Legacy"}]
    findings = run_recognizers(paths, settings, legacy_caches=legacy)
    assert any(f.recognizer_id == "legacy_cache" for f in findings)
