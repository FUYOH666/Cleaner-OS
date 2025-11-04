"""Модуль сканирования остатков удаленных приложений."""

import logging
from pathlib import Path
from typing import Any

from syscleaner.platform import IS_LINUX, IS_MACOS
from syscleaner.platform.linux import get_flatpak_apps, get_installed_packages, get_snap_apps
from syscleaner.platform.macos import get_installed_apps
from syscleaner.platform.paths import PlatformPaths
from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_application_support(paths: PlatformPaths) -> list[dict[str, Any]]:
    """
    Сканировать директорию поддержки приложений на остатки удаленных приложений.

    Args:
        paths: Объект PlatformPaths для получения путей.

    Returns:
        Список найденных остатков приложений.
    """
    results: list[dict[str, Any]] = []
    app_support_dir = paths.app_support_dir()

    if not app_support_dir.exists():
        logger.warning(f"Директория поддержки приложений не найдена: {app_support_dir}")
        return results

    # Получаем список установленных приложений в зависимости от платформы
    installed_apps: set[str] = set()

    if IS_MACOS:
        installed_apps = get_installed_apps()
    elif IS_LINUX:
        # Для Linux проверяем разные источники приложений
        installed_apps.update(get_installed_packages())
        installed_apps.update(get_flatpak_apps())
        installed_apps.update(get_snap_apps())

    try:
        for app_dir in app_support_dir.iterdir():
            if app_dir.is_dir():
                # Проверяем, есть ли соответствующее приложение
                app_name = app_dir.name.lower()
                # Простая проверка - если нет установленного приложения, возможно оно удалено
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
        logger.error(f"Нет доступа к директории поддержки приложений: {app_support_dir}")
    except Exception as e:
        logger.error(f"Ошибка при сканировании поддержки приложений: {e}")

    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)

