"""Smoke tests for filesystem scanners."""

from pathlib import Path

from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.caches import scan_caches
from syscleaner.scanner.trash import scan_trash


def test_scan_caches_finds_dir(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    cache_root = home / "Library" / "Caches"
    app_cache = cache_root / "TestApp"
    app_cache.mkdir(parents=True)
    (app_cache / "blob").write_bytes(b"x" * 5000)

    paths = PlatformPaths(home=home)
    results = scan_caches(paths, exclude_paths=[])
    assert len(results) >= 1
    assert results[0]["size_mb"] > 0


def test_scan_trash_empty(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    trash = home / ".Trash"
    trash.mkdir()
    paths = PlatformPaths(home=home)
    result = scan_trash(paths)
    assert result["count"] == 0
    assert result["size_bytes"] == 0


def test_scan_trash_with_file(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    trash = home / ".Trash"
    trash.mkdir()
    (trash / "old.txt").write_bytes(b"data" * 100)
    paths = PlatformPaths(home=home)
    result = scan_trash(paths)
    assert result["count"] >= 1
    assert result["size_bytes"] > 0
