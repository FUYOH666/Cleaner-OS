"""Платформо-специфичные модули."""

from syscleaner.platform.detector import IS_LINUX, IS_MACOS, Platform
from syscleaner.platform.paths import PlatformPaths

__all__ = ["Platform", "PlatformPaths", "IS_MACOS", "IS_LINUX"]

