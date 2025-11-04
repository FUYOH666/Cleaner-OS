"""Модуль сканирования кэшей."""

import logging
from pathlib import Path
from typing import Any

from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_caches(paths: PlatformPaths, exclude_paths: list[str]) -> list[dict[str, Any]]:
    """
    Сканировать кэши.

    Args:
        paths: Объект PlatformPaths для получения путей.
        exclude_paths: Пути для исключения.

    Returns:
        Список найденных кэшей.
    """
    results: list[dict[str, Any]] = []
    caches_dir = paths.cache_dir()

    if not caches_dir.exists():
        logger.warning(f"Директория кэшей не найдена: {caches_dir}")
        return results

    try:
        for cache_dir in caches_dir.iterdir():
            if cache_dir.is_dir():
                cache_path_str = str(cache_dir)
                # Проверяем исключения
                if any(exclude in cache_path_str for exclude in exclude_paths):
                    continue

                size = get_directory_size(cache_dir)
                if size > 0:
                    size_mb = size / (1024 * 1024)
                    size_value, size_unit = format_size(size)
                    results.append(
                        {
                            "path": str(cache_dir),
                            "name": cache_dir.name,
                            "size_bytes": size,
                            "size_mb": size_mb,
                            "size_formatted": f"{size_value:.2f} {size_unit}",
                        },
                    )
    except PermissionError:
        logger.error(f"Нет доступа к директории кэшей: {caches_dir}")
    except Exception as e:
        logger.error(f"Ошибка при сканировании кэшей: {e}")

    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)

