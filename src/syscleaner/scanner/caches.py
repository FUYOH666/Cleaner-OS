"""Cache directory scanning."""

import logging
from typing import Any

from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_caches(paths: PlatformPaths, exclude_paths: list[str]) -> list[dict[str, Any]]:
    """
    Scan user cache directories.

    Args:
        paths: Platform path resolver.
        exclude_paths: Path substrings to skip.

    Returns:
        List of cache entries with size metadata.
    """
    results: list[dict[str, Any]] = []
    caches_dir = paths.cache_dir()

    if not caches_dir.exists():
        logger.warning("Cache directory not found: %s", caches_dir)
        return results

    try:
        for cache_dir in caches_dir.iterdir():
            if cache_dir.is_dir():
                cache_path_str = str(cache_dir)
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
        logger.error("Permission denied reading cache directory: %s", caches_dir)
    except Exception as e:
        logger.error("Error scanning caches: %s", e)

    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)
