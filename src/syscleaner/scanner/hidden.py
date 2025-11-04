"""Модуль сканирования скрытых файлов."""

import logging
from pathlib import Path
from typing import Any

from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_hidden_files(paths: PlatformPaths, min_size_mb: float = 100) -> list[dict[str, Any]]:
    """
    Сканировать скрытые файлы и директории в домашней директории.

    Args:
        paths: Объект PlatformPaths для получения путей.
        min_size_mb: Минимальный размер для отчета в MB.

    Returns:
        Список найденных больших скрытых файлов/директорий.
    """
    results: list[dict[str, Any]] = []
    home = paths.home
    min_size_bytes = int(min_size_mb * 1024 * 1024)

    try:
        # Сканируем домашнюю директорию на скрытые файлы
        for item in home.iterdir():
            if item.name.startswith("."):
                try:
                    if item.is_file():
                        size = item.stat().st_size
                        if size >= min_size_bytes:
                            size_mb = size / (1024 * 1024)
                            size_value, size_unit = format_size(size)
                            results.append(
                                {
                                    "path": str(item),
                                    "name": item.name,
                                    "type": "file",
                                    "size_bytes": size,
                                    "size_mb": size_mb,
                                    "size_formatted": f"{size_value:.2f} {size_unit}",
                                },
                            )
                    elif item.is_dir():
                        try:
                            size = get_directory_size(item)
                            if size >= min_size_bytes:
                                size_mb = size / (1024 * 1024)
                                size_value, size_unit = format_size(size)
                                results.append(
                                    {
                                        "path": str(item),
                                        "name": item.name,
                                        "type": "directory",
                                        "size_bytes": size,
                                        "size_mb": size_mb,
                                        "size_formatted": f"{size_value:.2f} {size_unit}",
                                    },
                                )
                        except (OSError, PermissionError):
                            continue
                except (OSError, PermissionError) as e:
                    logger.debug(f"Ошибка при сканировании {item}: {e}")
                    continue
    except Exception as e:
        logger.error(f"Ошибка при сканировании скрытых файлов: {e}")

    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)

