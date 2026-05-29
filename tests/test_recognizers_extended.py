"""Additional recognizer tests."""

from pathlib import Path

from syscleaner.config import Settings
from syscleaner.platform.paths import PlatformPaths
from syscleaner.recognizers.registry import run_recognizers


def _run_one(tmp_path: Path, recognizer_id: str, rel_path: str) -> None:
    home = tmp_path / "home"
    target = home / rel_path
    target.mkdir(parents=True, exist_ok=True)
    (target / "data").write_bytes(b"y" * 4096)
    paths = PlatformPaths(home=home)
    settings = Settings()
    settings.recognizers.enabled = [recognizer_id]
    findings = run_recognizers(paths, settings)
    assert len(findings) >= 1
    assert findings[0].recognizer_id == recognizer_id


def test_hf_hub_recognizer(tmp_path: Path) -> None:
    _run_one(tmp_path, "hf_hub", ".cache/huggingface/hub")


def test_cursor_ide_recognizer(tmp_path: Path) -> None:
    _run_one(tmp_path, "cursor_ide", ".cache/Cursor")


def test_npm_cache_recognizer(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cache = home / ".npm" / "_cacache"
    cache.mkdir(parents=True)
    (cache / "x").write_bytes(b"z" * 2048)
    paths = PlatformPaths(home=home)
    settings = Settings()
    settings.recognizers.enabled = ["npm_cache"]
    findings = run_recognizers(paths, settings)
    assert any(f.recognizer_id == "npm_cache" for f in findings)
