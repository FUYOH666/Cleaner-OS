"""Recognizer protocol and shared utilities."""

from __future__ import annotations

import logging
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from syscleaner.models.entities import Finding, RiskTier
from syscleaner.scanner.utils import format_size, get_directory_size

if TYPE_CHECKING:
    from syscleaner.config import Settings
    from syscleaner.platform.paths import PlatformPaths

logger = logging.getLogger(__name__)


def path_size_finding(
    *,
    recognizer_id: str,
    category: str,
    title: str,
    path: Path,
    risk: RiskTier,
    description: str = "",
    metadata: dict | None = None,
) -> Finding | None:
    """Build a Finding from a path if it exists and has size."""
    if not path.exists():
        return None
    size = get_directory_size(path) if path.is_dir() else path.stat().st_size
    if size <= 0:
        return None
    size_value, size_unit = format_size(size)
    return Finding(
        id=f"{recognizer_id}:{path}",
        recognizer_id=recognizer_id,
        category=category,
        title=title,
        path=str(path),
        size_bytes=size,
        risk=risk,
        description=description or f"Size: {size_value:.2f} {size_unit}",
        metadata=metadata or {},
    )


def cli_available(name: str) -> bool:
    return shutil.which(name) is not None


class Recognizer(ABC):
    """Scan-only plugin; never deletes."""

    id: str
    category: str

    @abstractmethod
    def scan(self, paths: PlatformPaths, settings: Settings) -> list[Finding]:
        """Return findings for this recognizer."""
