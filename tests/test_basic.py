"""Базовые тесты для syscleaner."""

import tempfile
from pathlib import Path

import pytest

from syscleaner.config import load_config, ScanConfig, SecurityConfig, Settings
from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.trash import scan_trash
from syscleaner.scanner.utils import get_directory_size


def test_config_defaults() -> None:
    """Тест значений по умолчанию конфигурации."""
    settings = Settings()
    assert settings.scan.min_size_mb == 10
    assert settings.scan.check_security is True
    assert settings.security.check_ssh_permissions is True


def test_config_load_from_dict() -> None:
    """Тест загрузки конфигурации из словаря."""
    config_data = {
        "scan": {
            "min_size_mb": 20,
            "check_security": False,
        },
        "security": {
            "sensitive_patterns": ["*.test"],
        },
    }
    settings = Settings(**config_data)
    assert settings.scan.min_size_mb == 20
    assert settings.scan.check_security is False
    assert "*.test" in settings.security.sensitive_patterns


def test_get_directory_size(tmp_path: Path) -> None:
    """Тест получения размера директории."""
    # Создаем тестовую структуру
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()
    (test_dir / "file1.txt").write_text("test content")
    (test_dir / "file2.txt").write_text("more content")

    size = get_directory_size(test_dir)
    assert size > 0
    assert isinstance(size, int)


def test_scan_trash_empty(tmp_path: Path) -> None:
    """Тест сканирования пустой корзины."""
    # Создаем тестовую структуру
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    trash_dir = fake_home / ".Trash"
    trash_dir.mkdir()

    # Создаем PlatformPaths с тестовой домашней директорией
    paths = PlatformPaths(home=fake_home)

    result = scan_trash(paths)
    assert result["size_bytes"] == 0
    assert result["count"] == 0
    assert "path" in result


def test_scan_trash_with_files(tmp_path: Path) -> None:
    """Тест сканирования корзины с файлами."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    trash_dir = fake_home / ".Trash"
    trash_dir.mkdir()
    (trash_dir / "deleted_file.txt").write_text("deleted content")

    # Создаем PlatformPaths с тестовой домашней директорией
    paths = PlatformPaths(home=fake_home)

    result = scan_trash(paths)
    assert result["size_bytes"] > 0
    assert result["count"] == 1


def test_load_config_from_file(tmp_path: Path) -> None:
    """Тест загрузки конфигурации из файла."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
scan:
  min_size_mb: 50
  check_security: false
security:
  check_ssh_permissions: false
""",
    )

    settings = load_config(config_file)
    assert settings.scan.min_size_mb == 50
    assert settings.scan.check_security is False
    assert settings.security.check_ssh_permissions is False

