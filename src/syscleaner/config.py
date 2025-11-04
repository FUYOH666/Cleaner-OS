"""Модуль конфигурации."""

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class ScanConfig(BaseModel):
    """Настройки сканирования."""

    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "~/Library/Mail/",
            "~/Library/Messages/",
            "~/Library/Photos/",
        ],
    )
    min_size_mb: float = Field(default=10.0, description="Минимальный размер для отчета в MB")
    check_security: bool = Field(default=True, description="Проверять безопасность")
    check_project_artifacts: bool = Field(default=True, description="Проверять артефакты проектов")
    check_dependencies: bool = Field(default=True, description="Проверять зависимости")
    check_ml_cache: bool = Field(default=True, description="Проверять ML кэши")


class SecurityConfig(BaseModel):
    """Настройки безопасности."""

    sensitive_patterns: list[str] = Field(
        default_factory=lambda: [
            "*.env",
            "*credentials*",
            "*secret*",
            "*password*",
            "*token*",
            "*api_key*",
        ],
    )
    check_ssh_permissions: bool = Field(default=True, description="Проверять права SSH")
    check_file_permissions: bool = Field(default=True, description="Проверять права файлов")


class CleanupConfig(BaseModel):
    """Настройки очистки."""

    safe_to_delete_patterns: list[str] = Field(
        default_factory=lambda: [
            "**/__pycache__",
            "**/.DS_Store",
            "**/node_modules",
            "**/*.pyc",
            "**/.pytest_cache",
        ],
    )


class Settings(BaseSettings):
    """Основные настройки приложения."""

    scan: ScanConfig = Field(default_factory=ScanConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    cleanup: CleanupConfig = Field(default_factory=CleanupConfig)

    model_config = SettingsConfigDict(
        env_nested_delimiter="__",
        env_file_encoding="utf-8",
    )


def load_config(config_path: str | Path | None = None) -> Settings:
    """
    Загрузить конфигурацию из файла и переменных окружения.

    Args:
        config_path: Путь к config.yaml. Если None, ищет в текущей директории.

    Returns:
        Настроенный объект Settings.

    Raises:
        FileNotFoundError: Если config.yaml не найден и не задан config_path.
        ValidationError: Если конфигурация невалидна.
    """
    if config_path is None:
        # Ищем config.yaml в текущей директории или родительских
        current_dir = Path.cwd()
        config_path = current_dir / "config.yaml"
        if not config_path.exists():
            # Пробуем найти в родительских директориях
            for parent in current_dir.parents:
                potential_config = parent / "config.yaml"
                if potential_config.exists():
                    config_path = potential_config
                    break

    if isinstance(config_path, str):
        config_path = Path(config_path)

    if not config_path.exists():
        logger.warning(
            f"config.yaml не найден по пути {config_path}. Используются значения по умолчанию.",
        )
        return Settings()

    try:
        with config_path.open(encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f)

        # Расширяем пути с ~
        if "scan" in yaml_data and "exclude_paths" in yaml_data["scan"]:
            yaml_data["scan"]["exclude_paths"] = [
                os.path.expanduser(path) for path in yaml_data["scan"]["exclude_paths"]
            ]

        # Создаем Settings с данными из YAML
        settings = Settings(**yaml_data)
        logger.info(f"Конфигурация загружена из {config_path}")
        return settings

    except Exception as e:
        logger.error(f"Ошибка загрузки конфигурации из {config_path}: {e}")
        raise

