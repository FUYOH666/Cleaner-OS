"""Load third-party recognizers via entry points."""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

from typing import cast

from syscleaner.recognizers.base import Recognizer

logger = logging.getLogger(__name__)

_GROUP = "syscleaner.recognizers"


def load_plugin_recognizers() -> list[Recognizer]:
    """Discover recognizers registered under ``syscleaner.recognizers``."""
    eps = entry_points().select(group=_GROUP)
    loaded: list[Recognizer] = []
    for ep in eps:
        try:
            recognizer = ep.load()
            if callable(recognizer):
                recognizer = recognizer()
            if hasattr(recognizer, "scan") and hasattr(recognizer, "id"):
                loaded.append(cast(Recognizer, recognizer))
            else:
                logger.warning("Entry point %s is not a Recognizer", ep.name)
        except Exception as e:
            logger.error("Failed to load recognizer plugin %s: %s", ep.name, e)
    return loaded
