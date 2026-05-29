"""Duplicate file scanner tests."""

from pathlib import Path

from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.duplicates import scan_duplicate_files


def test_finds_duplicate_group(tmp_path: Path) -> None:
    home = tmp_path / "home"
    dev = home / "development"
    dev.mkdir(parents=True)
    content = b"x" * 2_000_000
    (dev / "a.bin").write_bytes(content)
    (dev / "b.bin").write_bytes(content)

    paths = PlatformPaths(home=home)
    result = scan_duplicate_files(paths, min_size_mb=1.0, max_groups=5)
    assert result["group_count"] >= 1
    assert result["waste_mb"] > 0
