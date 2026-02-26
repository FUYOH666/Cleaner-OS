"""Configuration module."""

import logging
import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class ScanConfig(BaseModel):
    """Scan settings."""

    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "~/Library/Mail/",
            "~/Library/Messages/",
            "~/Library/Photos/",
        ],
    )
    min_size_mb: float = Field(default=10.0, description="Min size for report (MB)")
    check_security: bool = Field(default=True, description="Check security")
    check_project_artifacts: bool = Field(default=True, description="Check project artifacts")
    check_dependencies: bool = Field(default=True, description="Check dependencies")
    check_ml_cache: bool = Field(default=True, description="Check ML caches")


class SecurityConfig(BaseModel):
    """Security settings."""

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
    check_ssh_permissions: bool = Field(default=True, description="Check SSH permissions")
    check_file_permissions: bool = Field(default=True, description="Check file permissions")


class CleanupConfig(BaseModel):
    """Cleanup settings."""

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
    """Application settings."""

    scan: ScanConfig = Field(default_factory=ScanConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    cleanup: CleanupConfig = Field(default_factory=CleanupConfig)

    model_config = SettingsConfigDict(
        env_nested_delimiter="__",
        env_file_encoding="utf-8",
    )


def load_config(config_path: str | Path | None = None) -> Settings:
    """
    Load configuration from file and environment variables.

    Args:
        config_path: Path to config.yaml. If None, searches current directory.

    Returns:
        Configured Settings instance.

    Raises:
        FileNotFoundError: If config.yaml not found and config_path not set.
        ValidationError: If configuration is invalid.
    """
    if config_path is None:
        current_dir = Path.cwd()
        config_path = current_dir / "config.yaml"
        if not config_path.exists():
            for parent in current_dir.parents:
                potential_config = parent / "config.yaml"
                if potential_config.exists():
                    config_path = potential_config
                    break

    if isinstance(config_path, str):
        config_path = Path(config_path)

    if not config_path.exists():
        logger.warning(
            "config.yaml not found at %s. Using defaults.",
            config_path,
        )
        return Settings()

    try:
        with config_path.open(encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f)

        if "scan" in yaml_data and "exclude_paths" in yaml_data["scan"]:
            yaml_data["scan"]["exclude_paths"] = [
                os.path.expanduser(path) for path in yaml_data["scan"]["exclude_paths"]
            ]

        settings = Settings(**yaml_data)
        logger.info("Config loaded from %s", config_path)
        return settings

    except Exception as e:
        logger.error("Config load error from %s: %s", config_path, e)
        raise
