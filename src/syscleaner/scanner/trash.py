"""Модуль сканирования корзины."""

import logging
from pathlib import Path
from typing import Any

from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_trash(paths: PlatformPaths) -> dict[str, Any]:
    """
    Сканировать корзину.

    Args:
        paths: Объект PlatformPaths для получения путей.

    Returns:
        Информация о корзине.
    """
    trash_dir = paths.trash_dir()

    if not trash_dir.exists():
        return {"path": str(trash_dir), "size_bytes": 0, "size_mb": 0.0, "count": 0}

    try:
        size = get_directory_size(trash_dir)
        count = sum(1 for _ in trash_dir.iterdir())
        size_mb = size / (1024 * 1024)
        size_value, size_unit = format_size(size)

        return {
            "path": str(trash_dir),
            "size_bytes": size,
            "size_mb": size_mb,
            "size_formatted": f"{size_value:.2f} {size_unit}",
            "count": count,
        }
    except (OSError, PermissionError) as e:
        logger.error(f"Ошибка при сканировании корзины: {e}")
        return {"path": str(trash_dir), "size_bytes": 0, "size_mb": 0.0, "count": 0}

