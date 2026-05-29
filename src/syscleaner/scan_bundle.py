"""Assemble unified ScanBundle from scanners and recognizers."""

from __future__ import annotations

import logging
from typing import Any

from syscleaner import __version__
from syscleaner.config import Settings
from syscleaner.models.entities import Finding, ScanBundle, SecurityIssue
from syscleaner.plan_builder import legacy_cleanup_to_findings
from syscleaner.platform import IS_LINUX, IS_MACOS
from syscleaner.platform.paths import PlatformPaths
from syscleaner.recognizers.registry import run_recognizers

logger = logging.getLogger(__name__)


def _platform_label() -> str:
    if IS_MACOS:
        import platform as plat

        return f"macOS {plat.release()}"
    if IS_LINUX:
        import platform as plat

        return f"Linux {plat.release()}"
    import platform as plat

    return plat.system()


def security_dict_to_issues(security_results: dict[str, Any]) -> list[SecurityIssue]:
    issues: list[SecurityIssue] = []
    for item in security_results.get("issues", []):
        issues.append(
            SecurityIssue(
                path=item.get("path", ""),
                category=item.get("category", "unknown"),
                severity=item.get("severity", "medium"),
                description=item.get("description", ""),
                recommendation=item.get("recommendation"),
            ),
        )
    return issues


def build_scan_bundle(
    *,
    scan_results: dict[str, Any],
    security_results: dict[str, Any],
    cleanup_analysis: dict[str, Any],
    ml_cache_results: dict[str, Any] | None,
    dependency_results: dict[str, Any] | None,
    paths: PlatformPaths,
    settings: Settings,
) -> ScanBundle:
    """Merge legacy scan output with recognizer findings."""
    recognizer_findings = run_recognizers(
        paths,
        settings,
        legacy_caches=scan_results.get("caches"),
    )
    legacy_findings = legacy_cleanup_to_findings(cleanup_analysis)

    # Deduplicate by path
    seen_paths: set[str] = set()
    merged: list[Finding] = []
    for f in recognizer_findings + legacy_findings:
        key = f.path or f.id
        if key in seen_paths:
            continue
        seen_paths.add(key)
        merged.append(f)

    return ScanBundle(
        tool_version=__version__,
        platform=_platform_label(),
        findings=merged,
        security_issues=security_dict_to_issues(security_results),
        scan_results=scan_results,
        security_results=security_results,
        cleanup_analysis=cleanup_analysis,
        ml_cache_results=ml_cache_results,
        dependency_results=dependency_results,
    )


def load_scan_bundle(data: dict[str, Any]) -> ScanBundle:
    """Load bundle from JSON; support legacy v0.3 format."""
    if "schema_version" in data and "findings" in data:
        return ScanBundle.model_validate(data)
    return ScanBundle(
        scan_results=data.get("scan_results", {}),
        security_results=data.get("security_results", {}),
        cleanup_analysis=data.get("cleanup_analysis", {}),
        ml_cache_results=data.get("ml_cache_results"),
        dependency_results=data.get("dependency_results"),
        findings=legacy_cleanup_to_findings(data.get("cleanup_analysis", {})),
        security_issues=security_dict_to_issues(data.get("security_results", {})),
    )
