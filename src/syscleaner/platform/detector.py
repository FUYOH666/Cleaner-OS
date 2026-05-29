"""Platform detection module."""

import platform
from enum import Enum


class Platform(str, Enum):
    """Supported platforms."""

    MACOS = "Darwin"
    LINUX = "Linux"
    UNKNOWN = "Unknown"


def detect_platform() -> Platform:
    """Detect the current platform.

    Returns:
        The detected platform.
    """
    system = platform.system()
    if system == "Darwin":
        return Platform.MACOS
    elif system == "Linux":
        return Platform.LINUX
    else:
        return Platform.UNKNOWN


# Global platform flags
CURRENT_PLATFORM = detect_platform()
IS_MACOS = CURRENT_PLATFORM == Platform.MACOS
IS_LINUX = CURRENT_PLATFORM == Platform.LINUX
IS_UNKNOWN = CURRENT_PLATFORM == Platform.UNKNOWN
