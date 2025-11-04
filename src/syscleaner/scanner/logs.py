"""Модуль сканирования логов."""

import logging
from pathlib import Path
from typing import Any

from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_logs(paths: PlatformPaths) -> list[dict[str, Any]]:
    """
    Сканировать логи.

    Args:
        paths: Объект PlatformPaths для получения путей.

    Returns:
        Список найденных логов.
    """
    results: list[dict[str, Any]] = []
    logs_dir = paths.logs_dir()

    if not logs_dir.exists():
        return results

    try:
        for log_dir in logs_dir.iterdir():
            if log_dir.is_dir():
                size = get_directory_size(log_dir)
                if size > 0:
                    size_mb = size / (1024 * 1024)
                    size_value, size_unit = format_size(size)
                    results.append(
                        {
                            "path": str(log_dir),
                            "name": log_dir.name,
                            "size_bytes": size,
                            "size_mb": size_mb,
                            "size_formatted": f"{size_value:.2f} {size_unit}",
                        },
                    )
    except PermissionError:
        logger.error(f"Нет доступа к директории логов: {logs_dir}")
    except Exception as e:
        logger.error(f"Ошибка при сканировании логов: {e}")

    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)

