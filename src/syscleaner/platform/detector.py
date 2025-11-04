"""Модуль определения платформы."""

import platform
import sys
from enum import Enum


class Platform(str, Enum):
    """Поддерживаемые платформы."""

    MACOS = "Darwin"
    LINUX = "Linux"
    UNKNOWN = "Unknown"


def detect_platform() -> Platform:
    """
    Определить текущую платформу.

    Returns:
        Текущая платформа.
    """
    system = platform.system()
    if system == "Darwin":
        return Platform.MACOS
    elif system == "Linux":
        return Platform.LINUX
    else:
        return Platform.UNKNOWN


# Глобальные переменные для определения платформы
CURRENT_PLATFORM = detect_platform()
IS_MACOS = CURRENT_PLATFORM == Platform.MACOS
IS_LINUX = CURRENT_PLATFORM == Platform.LINUX
IS_UNKNOWN = CURRENT_PLATFORM == Platform.UNKNOWN

