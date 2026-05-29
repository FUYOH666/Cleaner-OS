"""Recognizer registry and execution."""

from __future__ import annotations

import logging

from syscleaner.config import Settings
from syscleaner.models.entities import Finding
from syscleaner.platform.paths import PlatformPaths
from syscleaner.recognizers.builtin import (
    BUILTIN_PATH_RECOGNIZERS,
    LegacyCacheRecognizer,
    OrphanedAppSupportRecognizer,
    enrich_finding_cli_metadata,
)

logger = logging.getLogger(__name__)

DEFAULT_ENABLED = [
    "uv_cache",
    "cursor_ide",
    "cursor_logs",
    "hf_hub",
    "ollama",
    "playwright",
    "xcode_derived",
    "xcode_archives",
    "npm_cache",
    "homebrew_cache",
    "pip_cache",
    "orphaned_app_support",
    "docker_cache",
]


def run_recognizers(
    paths: PlatformPaths,
    settings: Settings,
    *,
    enabled: list[str] | None = None,
    legacy_caches: list[dict] | None = None,
) -> list[Finding]:
    """Run all enabled recognizers and return combined findings."""
    enabled_ids = set(enabled or settings.recognizers.enabled or DEFAULT_ENABLED)
    findings: list[Finding] = []

    for recognizer in BUILTIN_PATH_RECOGNIZERS:
        if recognizer.id not in enabled_ids:
            continue
        try:
            findings.extend(recognizer.scan(paths, settings))
        except Exception as e:
            logger.error("Recognizer %s failed: %s", recognizer.id, e)

    if "orphaned_app_support" in enabled_ids:
        try:
            findings.extend(OrphanedAppSupportRecognizer().scan(paths, settings))
        except Exception as e:
            logger.error("orphaned_app_support failed: %s", e)

    if legacy_caches:
        try:
            findings.extend(LegacyCacheRecognizer(legacy_caches).scan(paths, settings))
        except Exception as e:
            logger.error("legacy_cache failed: %s", e)

    return enrich_finding_cli_metadata(findings)
