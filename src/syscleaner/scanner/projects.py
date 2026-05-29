"""Project artifact scan module."""

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from syscleaner.scanner.utils import format_size, get_directory_size

logger = logging.getLogger(__name__)


def scan_project_artifacts(
    projects_dirs: list[Path],
    safe_patterns: list[str],
) -> list[dict[str, Any]]:
    """Scan projects for build artifacts and clutter.

    Args:
        projects_dirs: Directories containing projects.
        safe_patterns: Patterns for files safe to delete.

    Returns:
        List of discovered artifacts grouped by type.
    """
    results: list[dict[str, Any]] = []
    artifact_types: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for projects_dir in projects_dirs:
        if not projects_dir.exists():
            logger.debug("Projects directory not found: %s", projects_dir)
            continue

        try:
            # Standard artifact patterns
            patterns = {
                "__pycache__": "**/__pycache__",
                ".pytest_cache": "**/.pytest_cache",
                ".DS_Store": "**/.DS_Store",
                "node_modules": "**/node_modules",
                "venv": "**/venv",
                ".venv": "**/.venv",
                "*.pyc": "**/*.pyc",
                ".mypy_cache": "**/.mypy_cache",
                ".ruff_cache": "**/.ruff_cache",
                "dist": "**/dist",
                "build": "**/build",
                "*.egg-info": "**/*.egg-info",
            }

            for artifact_name, pattern in patterns.items():
                for artifact_path in projects_dir.rglob(pattern):
                    if artifact_path.exists():
                        if artifact_path.is_file():
                            size = artifact_path.stat().st_size
                        else:
                            size = get_directory_size(artifact_path)

                        if size > 0:
                            size_mb = size / (1024 * 1024)
                            size_value, size_unit = format_size(size)
                            artifact_types[artifact_name].append(
                                {
                                    "path": str(artifact_path),
                                    "size_bytes": size,
                                    "size_mb": size_mb,
                                    "size_formatted": f"{size_value:.2f} {size_unit}",
                                },
                            )
        except Exception as e:
            logger.debug("Error scanning artifacts in %s: %s", projects_dir, e)

    # Aggregate results by artifact type
    for artifact_name, artifacts in artifact_types.items():
        total_size = sum(a["size_bytes"] for a in artifacts)
        total_size_mb = total_size / (1024 * 1024)
        total_size_formatted = format_size(total_size)
        results.append(
            {
                "type": artifact_name,
                "count": len(artifacts),
                "total_size_bytes": total_size,
                "total_size_mb": total_size_mb,
                "total_size_formatted": f"{total_size_formatted[0]:.2f} {total_size_formatted[1]}",
                "items": artifacts[:10],  # Show only the first 10 items
            },
        )

    return sorted(results, key=lambda x: x["total_size_bytes"], reverse=True)
