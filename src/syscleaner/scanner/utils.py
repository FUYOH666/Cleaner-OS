"""Shared scanning utilities."""

from pathlib import Path


def get_directory_size(path: Path) -> int:
    """
    Return directory size in bytes.

    Args:
        path: Directory path.

    Returns:
        Total size in bytes.
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
    Format a byte size for display.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Tuple of (numeric value, unit label).
    """
    value: float = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024.0:
            return (value, unit)
        value /= 1024.0
    return (value, "PB")
