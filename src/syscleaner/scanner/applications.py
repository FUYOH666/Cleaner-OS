"""Scan module for leftovers from removed applications."""

import logging
from typing import Any

from syscleaner.platform import IS_LINUX, IS_MACOS
from syscleaner.platform.linux import get_flatpak_apps, get_installed_packages, get_snap_apps
from syscleaner.platform.macos import get_installed_apps
from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_application_support(paths: PlatformPaths) -> list[dict[str, Any]]:
    """Scan application support directories for leftovers from removed apps.

    Args:
        paths: PlatformPaths instance for resolving paths.

    Returns:
        List of application support directories and sizes.
    """
    results: list[dict[str, Any]] = []
    app_support_dir = paths.app_support_dir()

    if not app_support_dir.exists():
        logger.warning("Application support directory not found: %s", app_support_dir)
        return results

    # Collect installed application names for the current platform
    installed_apps: set[str] = set()

    if IS_MACOS:
        installed_apps = get_installed_apps()
    elif IS_LINUX:
        # On Linux, check multiple application sources
        installed_apps.update(get_installed_packages())
        installed_apps.update(get_flatpak_apps())
        installed_apps.update(get_snap_apps())

    try:
        for app_dir in app_support_dir.iterdir():
            if app_dir.is_dir():
                # Check whether a matching application is still installed
                app_name = app_dir.name.lower()
                # Simple heuristic: no installed app may mean it was removed
                size = get_directory_size(app_dir)
                if size > 0:
                    size_mb = size / (1024 * 1024)
                    size_value, size_unit = format_size(size)
                    results.append(
                        {
                            "path": str(app_dir),
                            "name": app_dir.name,
                            "size_bytes": size,
                            "size_mb": size_mb,
                            "size_formatted": f"{size_value:.2f} {size_unit}",
                            "possibly_orphaned": app_name not in installed_apps,
                        },
                    )
    except PermissionError:
        logger.error("No access to application support directory: %s", app_support_dir)
    except Exception as e:
        logger.error("Error scanning application support: %s", e)

    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)
