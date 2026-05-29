"""Duplicate file finder (MVP): size grouping + content hash."""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from pathlib import Path

from syscleaner.platform.paths import PlatformPaths

logger = logging.getLogger(__name__)

_DEFAULT_SEARCH = ("development", "Downloads", "Documents")
_MAX_DEPTH = 6
_MAX_FILES_PER_SIZE = 32


def _file_hash(path: Path, chunk: int = 65536) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def scan_duplicate_files(
    paths: PlatformPaths,
    *,
    min_size_mb: float = 1.0,
    max_groups: int = 20,
) -> dict:
    """Find duplicate files under common user directories.

    Returns summary dict suitable for scan JSON ``duplicates`` key.
    """
    min_bytes = int(min_size_mb * 1024 * 1024)
    by_size: dict[int, list[Path]] = defaultdict(list)
    scanned = 0

    roots = [paths.home / name for name in _DEFAULT_SEARCH]
    for root in roots:
        if not root.exists():
            continue
        try:
            for entry in root.rglob("*"):
                if not entry.is_file():
                    continue
                if entry.is_symlink():
                    continue
                depth = len(entry.relative_to(root).parts)
                if depth > _MAX_DEPTH:
                    continue
                try:
                    size = entry.stat().st_size
                except OSError:
                    continue
                if size < min_bytes:
                    continue
                by_size[size].append(entry)
                scanned += 1
                if scanned > 5000:
                    logger.warning("Duplicate scan file limit reached")
                    break
        except OSError as e:
            logger.warning("Duplicate scan skipped for %s: %s", root, e)

    groups: list[dict] = []
    for size, file_list in sorted(by_size.items(), key=lambda x: -x[0]):
        if len(file_list) < 2:
            continue
        if len(file_list) > _MAX_FILES_PER_SIZE:
            file_list = file_list[:_MAX_FILES_PER_SIZE]
        by_hash: dict[str, list[str]] = defaultdict(list)
        for fp in file_list:
            try:
                by_hash[_file_hash(fp)].append(str(fp))
            except OSError as e:
                logger.debug("Hash skip %s: %s", fp, e)
        for digest, paths_str in by_hash.items():
            if len(paths_str) < 2:
                continue
            groups.append(
                {
                    "size_bytes": size,
                    "hash": digest[:16],
                    "paths": paths_str,
                    "count": len(paths_str),
                    "waste_bytes": size * (len(paths_str) - 1),
                },
            )
            if len(groups) >= max_groups:
                break
        if len(groups) >= max_groups:
            break

    waste = sum(g["waste_bytes"] for g in groups)
    return {
        "groups": groups,
        "group_count": len(groups),
        "waste_mb": round(waste / (1024 * 1024), 2),
        "min_size_mb": min_size_mb,
    }
