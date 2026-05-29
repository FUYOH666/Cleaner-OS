"""Hidden file scan module."""

import logging
from typing import Any

from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_hidden_files(paths: PlatformPaths, min_size_mb: float = 100) -> list[dict[str, Any]]:
    """Scan hidden files and directories in the home directory.

    Args:
        paths: PlatformPaths instance for resolving paths.
        min_size_mb: Minimum size in MB to include in the report.

    Returns:
        List of large hidden files and directories.
    """
    results: list[dict[str, Any]] = []
    home = paths.home
    min_size_bytes = int(min_size_mb * 1024 * 1024)

    try:
        # Scan home directory for hidden entries
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
                    logger.debug("Error scanning %s: %s", item, e)
                    continue
    except Exception as e:
        logger.error("Error scanning hidden files: %s", e)

    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)
