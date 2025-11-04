"""Общие утилиты для сканирования."""

from pathlib import Path


def get_directory_size(path: Path) -> int:
    """
    Получить размер директории в байтах.

    Args:
        path: Путь к директории.

    Returns:
        Размер в байтах.
    """
    total_size = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                try:
                    total_size += entry.stat().st_size
                except (OSError, PermissionError):
                    continue
    except (OSError, PermissionError):
        pass
    return total_size


def format_size(size_bytes: int) -> tuple[float, str]:
    """
    Форматировать размер в читаемый формат.

    Args:
        size_bytes: Размер в байтах.

    Returns:
        Кортеж (размер, единица измерения).
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return (size_bytes, unit)
        size_bytes /= 1024.0
    return (size_bytes, "PB")

