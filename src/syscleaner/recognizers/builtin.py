"""Built-in path and cache recognizers."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from pathlib import Path

from syscleaner.config import Settings
from syscleaner.models.entities import Finding, RiskTier
from syscleaner.platform import IS_MACOS
from syscleaner.platform.paths import PlatformPaths
from syscleaner.recognizers.base import Recognizer, cli_available, path_size_finding
from syscleaner.scanner.applications import scan_application_support

logger = logging.getLogger(__name__)


class PathRecognizer(Recognizer):
    """Generic directory recognizer."""

    def __init__(
        self,
        recognizer_id: str,
        category: str,
        title: str,
        path_fn: Callable[[PlatformPaths], Path],
        risk: RiskTier,
        platforms: frozenset[str] | None = None,
    ) -> None:
        self.id = recognizer_id
        self.category = category
        self._title = title
        self._path_fn = path_fn
        self._risk = risk
        self._platforms = platforms

    def scan(self, paths: PlatformPaths, settings: Settings) -> list[Finding]:
        if self._platforms:
            current = "darwin" if sys.platform == "darwin" else "linux"
            if current not in self._platforms:
                return []
        target = self._path_fn(paths)
        finding = path_size_finding(
            recognizer_id=self.id,
            category=self.category,
            title=self._title,
            path=target,
            risk=self._risk,
            metadata={"native_cli": _native_cli_hint(self.id)},
        )
        return [finding] if finding else []


def _native_cli_hint(recognizer_id: str) -> str | None:
    hints = {
        "uv_cache": "uv cache prune",
        "hf_hub": "hf cache prune",
        "homebrew_cache": "brew cleanup -s",
        "npm_cache": "npm cache clean --force",
        "docker_cache": "docker system prune",
    }
    return hints.get(recognizer_id)


def _uv_cache(paths: PlatformPaths) -> Path:
    return paths.home / ".cache" / "uv"


def _cursor_cache(paths: PlatformPaths) -> Path:
    return paths.home / ".cache" / "Cursor"


def _cursor_config_logs(paths: PlatformPaths) -> Path:
    return paths.home / ".config" / "Cursor" / "logs"


def _hf_hub(paths: PlatformPaths) -> Path:
    hf_home = paths.home / ".cache" / "huggingface"
    hub = hf_home / "hub"
    return hub if hub.exists() else hf_home


def _ollama(paths: PlatformPaths) -> Path:
    return paths.home / ".ollama" / "models"


def _playwright(paths: PlatformPaths) -> Path:
    if IS_MACOS:
        return paths.home / "Library" / "Caches" / "ms-playwright"
    return paths.home / ".cache" / "ms-playwright"


def _xcode_derived(paths: PlatformPaths) -> Path:
    return paths.home / "Library" / "Developer" / "Xcode" / "DerivedData"


def _xcode_archives(paths: PlatformPaths) -> Path:
    return paths.home / "Library" / "Developer" / "Xcode" / "Archives"


def _npm_cache(paths: PlatformPaths) -> Path:
    npm_dir = paths.home / ".npm"
    if npm_dir.exists():
        return npm_dir / "_cacache"
    return npm_dir


def _homebrew_cache(paths: PlatformPaths) -> Path:
    return paths.home / "Library" / "Caches" / "Homebrew"


def _pip_cache(paths: PlatformPaths) -> Path:
    return paths.home / "Library" / "Caches" / "pip" if IS_MACOS else paths.home / ".cache" / "pip"


def _docker_data(paths: PlatformPaths) -> Path:
    if IS_MACOS:
        return (
            paths.home
            / "Library"
            / "Containers"
            / "com.docker.docker"
            / "Data"
        )
    return paths.home / ".docker"


BUILTIN_PATH_RECOGNIZERS: list[PathRecognizer] = [
    PathRecognizer("uv_cache", "python", "uv package cache", _uv_cache, RiskTier.SAFE),
    PathRecognizer(
        "cursor_ide",
        "ai-era",
        "Cursor IDE cache",
        _cursor_cache,
        RiskTier.MODERATE,
    ),
    PathRecognizer(
        "cursor_logs",
        "ai-era",
        "Cursor log files",
        _cursor_config_logs,
        RiskTier.SAFE,
        platforms=frozenset({"linux"}),
    ),
    PathRecognizer("hf_hub", "ml", "Hugging Face hub cache", _hf_hub, RiskTier.MODERATE),
    PathRecognizer("ollama", "ml", "Ollama models", _ollama, RiskTier.MODERATE),
    PathRecognizer(
        "playwright",
        "devtool",
        "Playwright browser cache",
        _playwright,
        RiskTier.MODERATE,
    ),
    PathRecognizer(
        "xcode_derived",
        "devtool",
        "Xcode DerivedData",
        _xcode_derived,
        RiskTier.SAFE,
        platforms=frozenset({"darwin"}),
    ),
    PathRecognizer(
        "xcode_archives",
        "devtool",
        "Xcode Archives",
        _xcode_archives,
        RiskTier.MODERATE,
        platforms=frozenset({"darwin"}),
    ),
    PathRecognizer("npm_cache", "nodejs", "npm cache", _npm_cache, RiskTier.SAFE),
    PathRecognizer(
        "homebrew_cache",
        "packagemanager",
        "Homebrew cache",
        _homebrew_cache,
        RiskTier.SAFE,
        platforms=frozenset({"darwin"}),
    ),
    PathRecognizer("pip_cache", "python", "pip cache", _pip_cache, RiskTier.SAFE),
    PathRecognizer(
        "docker_cache",
        "devtool",
        "Docker local data",
        _docker_data,
        RiskTier.MODERATE,
    ),
]


class OrphanedAppSupportRecognizer(Recognizer):
    """macOS Application Support folders without matching installed apps."""

    id = "orphaned_app_support"
    category = "applications"

    def scan(self, paths: PlatformPaths, settings: Settings) -> list[Finding]:
        if not IS_MACOS:
            return []
        findings: list[Finding] = []
        for item in scan_application_support(paths):
            if not item.get("possibly_orphaned"):
                continue
            path = item["path"]
            size = item["size_bytes"]
            findings.append(
                Finding(
                    id=f"{self.id}:{path}",
                    recognizer_id=self.id,
                    category=self.category,
                    title=f"Orphaned app support: {item['name']}",
                    path=path,
                    size_bytes=size,
                    risk=RiskTier.MODERATE,
                    description="Application Support without matching /Applications entry",
                    metadata={"app_name": item["name"]},
                ),
            )
        return findings


class LegacyCacheRecognizer(Recognizer):
    """Wrap legacy cache scanner entries as findings."""

    id = "legacy_caches"
    category = "caches"

    def __init__(self, cache_items: list[dict]) -> None:
        self._items = cache_items

    def scan(self, paths: PlatformPaths, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for item in self._items:
            if item.get("size_mb", 0) < settings.scan.min_size_mb:
                continue
            findings.append(
                Finding(
                    id=f"cache:{item['path']}",
                    recognizer_id="legacy_cache",
                    category="caches",
                    title=item.get("name", "Cache"),
                    path=item["path"],
                    size_bytes=int(item.get("size_bytes", item["size_mb"] * 1024 * 1024)),
                    risk=RiskTier.MODERATE,
                    description=f"Large app cache: {item.get('name', '')}",
                ),
            )
        return findings


def enrich_finding_cli_metadata(findings: list[Finding]) -> list[Finding]:
    """Attach whether native CLI is available for known recognizers."""
    cli_map = {
        "uv_cache": ("uv", ["uv", "cache", "prune"]),
        "hf_hub": ("hf", ["hf", "cache", "prune"]),
        "homebrew_cache": ("brew", ["brew", "cleanup", "-s"]),
        "npm_cache": ("npm", ["npm", "cache", "clean", "--force"]),
        "docker_cache": ("docker", ["docker", "system", "prune", "-f"]),
    }
    enriched: list[Finding] = []
    for f in findings:
        meta = dict(f.metadata)
        if f.recognizer_id in cli_map:
            bin_name, cmd = cli_map[f.recognizer_id]
            meta["native_cli"] = " ".join(cmd)
            meta["cli_available"] = cli_available(bin_name)
        enriched.append(f.model_copy(update={"metadata": meta}))
    return enriched
