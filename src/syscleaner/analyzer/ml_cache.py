"""ML model cache analysis module."""

import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from syscleaner.platform.paths import PlatformPaths

logger = logging.getLogger(__name__)


class MLModelCache:
    """Cached ML model metadata."""

    def __init__(
        self,
        name: str,
        path: Path,
        size_bytes: int,
        last_accessed: float | None = None,
        cache_type: str = "unknown",
    ) -> None:
        """Initialize model cache metadata.

        Args:
            name: Model name.
            path: Path to the model.
            size_bytes: Size in bytes.
            last_accessed: Last access timestamp.
            cache_type: Cache backend (huggingface, pytorch, tensorflow, etc.).
        """
        self.name = name
        self.path = path
        self.size_bytes = size_bytes
        self.last_accessed = last_accessed
        self.cache_type = cache_type

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dictionary."""
        return {
            "name": self.name,
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "size_mb": self.size_bytes / (1024 * 1024),
            "size_gb": self.size_bytes / (1024 * 1024 * 1024),
            "last_accessed": self.last_accessed,
            "cache_type": self.cache_type,
        }


def get_file_size(path: Path) -> int:
    """Return the size of a file or directory tree.

    Args:
        path: File or directory path.

    Returns:
        Size in bytes.
    """
    if path.is_file():
        try:
            return path.stat().st_size
        except (OSError, PermissionError):
            return 0

    total_size = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                try:
                    total_size += entry.stat().st_size
                except (OSError, PermissionError):
                    continue
    except (OSError, PermissionError):
        pass

    return total_size


def get_last_accessed_time(path: Path) -> float | None:
    """Return the last access time for a file or directory.

    Args:
        path: File or directory path.

    Returns:
        Last access timestamp, or None.
    """
    try:
        stat = path.stat()
        return max(stat.st_atime, stat.st_mtime)
    except (OSError, PermissionError):
        return None


def scan_huggingface_cache(cache_dir: Path) -> list[MLModelCache]:
    """Scan the Hugging Face cache directory.

    Args:
        cache_dir: Hugging Face cache root.

    Returns:
        List of discovered models and datasets.
    """
    models: list[MLModelCache] = []

    hub_dir = cache_dir / "hub"
    if not hub_dir.exists():
        return models

    try:
        for model_dir in hub_dir.iterdir():
            if model_dir.is_dir() and "--" in model_dir.name:
                model_name = model_dir.name.replace("models--", "").replace("--", "/")
                size = get_file_size(model_dir)
                last_accessed = get_last_accessed_time(model_dir)

                if size > 0:
                    models.append(
                        MLModelCache(
                            name=model_name,
                            path=model_dir,
                            size_bytes=size,
                            last_accessed=last_accessed,
                            cache_type="huggingface",
                        ),
                    )

        datasets_dir = cache_dir / "datasets"
        if datasets_dir.exists():
            for dataset_dir in datasets_dir.iterdir():
                if dataset_dir.is_dir():
                    dataset_name = dataset_dir.name
                    size = get_file_size(dataset_dir)
                    last_accessed = get_last_accessed_time(dataset_dir)

                    if size > 0:
                        models.append(
                            MLModelCache(
                                name=f"dataset:{dataset_name}",
                                path=dataset_dir,
                                size_bytes=size,
                                last_accessed=last_accessed,
                                cache_type="huggingface_dataset",
                            ),
                        )

    except Exception as e:
        logger.error("Error scanning Hugging Face cache: %s", e)

    return models


def scan_pytorch_cache(cache_dir: Path) -> list[MLModelCache]:
    """Scan the PyTorch cache directory.

    Args:
        cache_dir: PyTorch cache root.

    Returns:
        List of discovered checkpoints and datasets.
    """
    models: list[MLModelCache] = []

    try:
        hub_dir = cache_dir / "hub" / "checkpoints"
        if hub_dir.exists():
            for checkpoint_file in hub_dir.iterdir():
                if checkpoint_file.is_file():
                    size = get_file_size(checkpoint_file)
                    last_accessed = get_last_accessed_time(checkpoint_file)

                    if size > 0:
                        models.append(
                            MLModelCache(
                                name=checkpoint_file.stem,
                                path=checkpoint_file,
                                size_bytes=size,
                                last_accessed=last_accessed,
                                cache_type="pytorch",
                            ),
                        )

        datasets_dir = cache_dir / "datasets"
        if datasets_dir.exists():
            for dataset_dir in datasets_dir.iterdir():
                if dataset_dir.is_dir():
                    size = get_file_size(dataset_dir)
                    last_accessed = get_last_accessed_time(dataset_dir)

                    if size > 0:
                        models.append(
                            MLModelCache(
                                name=f"dataset:{dataset_dir.name}",
                                path=dataset_dir,
                                size_bytes=size,
                                last_accessed=last_accessed,
                                cache_type="pytorch_dataset",
                            ),
                        )

    except Exception as e:
        logger.error("Error scanning PyTorch cache: %s", e)

    return models


def scan_tensorflow_cache(cache_dir: Path) -> list[MLModelCache]:
    """Scan the TensorFlow cache directory.

    Args:
        cache_dir: TensorFlow cache root.

    Returns:
        List of discovered models and datasets.
    """
    models: list[MLModelCache] = []

    try:
        saved_models_dir = cache_dir / "saved_models"
        if saved_models_dir.exists():
            for model_dir in saved_models_dir.iterdir():
                if model_dir.is_dir():
                    size = get_file_size(model_dir)
                    last_accessed = get_last_accessed_time(model_dir)

                    if size > 0:
                        models.append(
                            MLModelCache(
                                name=model_dir.name,
                                path=model_dir,
                                size_bytes=size,
                                last_accessed=last_accessed,
                                cache_type="tensorflow",
                            ),
                        )

        datasets_dir = cache_dir / "datasets"
        if datasets_dir.exists():
            for dataset_dir in datasets_dir.iterdir():
                if dataset_dir.is_dir():
                    size = get_file_size(dataset_dir)
                    last_accessed = get_last_accessed_time(dataset_dir)

                    if size > 0:
                        models.append(
                            MLModelCache(
                                name=f"dataset:{dataset_dir.name}",
                                path=dataset_dir,
                                size_bytes=size,
                                last_accessed=last_accessed,
                                cache_type="tensorflow_dataset",
                            ),
                        )

    except Exception as e:
        logger.error("Error scanning TensorFlow cache: %s", e)

    return models


def scan_ml_cache(paths: PlatformPaths) -> dict[str, Any]:
    """Scan all configured ML cache directories.

    Args:
        paths: PlatformPaths instance for resolving paths.

    Returns:
        ML cache scan results.
    """
    all_models: list[MLModelCache] = []
    cache_dirs = paths.ml_cache_dirs()

    logger.info("Scanning ML caches in %d directories", len(cache_dirs))

    for cache_dir in cache_dirs:
        cache_dir_name = cache_dir.name.lower()

        if "huggingface" in cache_dir_name:
            models = scan_huggingface_cache(cache_dir)
            all_models.extend(models)
            logger.info("Found %d models/datasets in Hugging Face cache", len(models))
        elif "torch" in cache_dir_name:
            models = scan_pytorch_cache(cache_dir)
            all_models.extend(models)
            logger.info("Found %d models/datasets in PyTorch cache", len(models))
        elif "tensorflow" in cache_dir_name or "keras" in cache_dir_name:
            models = scan_tensorflow_cache(cache_dir)
            all_models.extend(models)
            logger.info("Found %d models/datasets in TensorFlow cache", len(models))

    total_size = sum(model.size_bytes for model in all_models)
    models_by_type = defaultdict(list)

    for model in all_models:
        models_by_type[model.cache_type].append(model)

    # Unused if not accessed in the last 30 days
    current_time = time.time()
    thirty_days_ago = current_time - (30 * 24 * 60 * 60)
    unused_models = [
        model
        for model in all_models
        if model.last_accessed is not None and model.last_accessed < thirty_days_ago
    ]

    unused_size = sum(model.size_bytes for model in unused_models)

    from syscleaner.hf_cli import enrich_ml_cache_results

    results = {
        "total_models": len(all_models),
        "total_size_bytes": total_size,
        "total_size_gb": total_size / (1024 * 1024 * 1024),
        "models_by_type": {
            cache_type: [model.to_dict() for model in models]
            for cache_type, models in models_by_type.items()
        },
        "unused_models_count": len(unused_models),
        "unused_size_bytes": unused_size,
        "unused_size_gb": unused_size / (1024 * 1024 * 1024),
        "models": [
            m.to_dict() for m in sorted(all_models, key=lambda x: x.size_bytes, reverse=True)
        ],
    }
    return enrich_ml_cache_results(results)
