"""Модуль анализа кэша ML моделей."""

import logging
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from syscleaner.platform.paths import PlatformPaths

logger = logging.getLogger(__name__)


class MLModelCache:
    """Информация о модели в кэше."""

    def __init__(
        self,
        name: str,
        path: Path,
        size_bytes: int,
        last_accessed: float | None = None,
        cache_type: str = "unknown",
    ) -> None:
        """
        Инициализация информации о модели.

        Args:
            name: Имя модели.
            path: Путь к модели.
            size_bytes: Размер в байтах.
            last_accessed: Время последнего доступа (timestamp).
            cache_type: Тип кэша (huggingface, pytorch, tensorflow, etc.).
        """
        self.name = name
        self.path = path
        self.size_bytes = size_bytes
        self.last_accessed = last_accessed
        self.cache_type = cache_type

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать в словарь."""
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
    """
    Получить размер файла или директории.

    Args:
        path: Путь к файлу или директории.

    Returns:
        Размер в байтах.
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
    """
    Получить время последнего доступа к файлу/директории.

    Args:
        path: Путь к файлу или директории.

    Returns:
        Timestamp последнего доступа или None.
    """
    try:
        stat = path.stat()
        return max(stat.st_atime, stat.st_mtime)
    except (OSError, PermissionError):
        return None


def scan_huggingface_cache(cache_dir: Path) -> list[MLModelCache]:
    """
    Сканировать Hugging Face кэш.

    Args:
        cache_dir: Директория кэша Hugging Face.

    Returns:
        Список найденных моделей.
    """
    models: list[MLModelCache] = []

    # Hugging Face хранит модели в hub/
    hub_dir = cache_dir / "hub"
    if not hub_dir.exists():
        return models

    try:
        # Модели хранятся в структуре: hub/models--{org}--{model_name}/
        for model_dir in hub_dir.iterdir():
            if model_dir.is_dir() and "--" in model_dir.name:
                # Извлекаем имя модели из структуры
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

        # Также проверяем datasets
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
        logger.error(f"Ошибка при сканировании Hugging Face кэша: {e}")

    return models


def scan_pytorch_cache(cache_dir: Path) -> list[MLModelCache]:
    """
    Сканировать PyTorch кэш.

    Args:
        cache_dir: Директория кэша PyTorch.

    Returns:
        Список найденных моделей и кэшей.
    """
    models: list[MLModelCache] = []

    try:
        # PyTorch хранит предзагруженные модели в hub/checkpoints/
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

        # Также проверяем datasets
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
        logger.error(f"Ошибка при сканировании PyTorch кэша: {e}")

    return models


def scan_tensorflow_cache(cache_dir: Path) -> list[MLModelCache]:
    """
    Сканировать TensorFlow кэш.

    Args:
        cache_dir: Директория кэша TensorFlow.

    Returns:
        Список найденных моделей.
    """
    models: list[MLModelCache] = []

    try:
        # TensorFlow хранит модели в saved_models/
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

        # Проверяем датасеты
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
        logger.error(f"Ошибка при сканировании TensorFlow кэша: {e}")

    return models


def scan_ml_cache(paths: PlatformPaths) -> dict[str, Any]:
    """
    Сканировать все ML кэши.

    Args:
        paths: Объект PlatformPaths для получения путей.

    Returns:
        Словарь с результатами сканирования.
    """
    all_models: list[MLModelCache] = []
    cache_dirs = paths.ml_cache_dirs()

    logger.info(f"Сканирование ML кэшей в {len(cache_dirs)} директориях")

    for cache_dir in cache_dirs:
        cache_dir_name = cache_dir.name.lower()

        if "huggingface" in cache_dir_name:
            models = scan_huggingface_cache(cache_dir)
            all_models.extend(models)
            logger.info(f"Найдено {len(models)} моделей/датасетов в Hugging Face кэше")
        elif "torch" in cache_dir_name:
            models = scan_pytorch_cache(cache_dir)
            all_models.extend(models)
            logger.info(f"Найдено {len(models)} моделей/датасетов в PyTorch кэше")
        elif "tensorflow" in cache_dir_name or "keras" in cache_dir_name:
            models = scan_tensorflow_cache(cache_dir)
            all_models.extend(models)
            logger.info(f"Найдено {len(models)} моделей/датасетов в TensorFlow кэше")

    # Анализ результатов
    total_size = sum(model.size_bytes for model in all_models)
    models_by_type = defaultdict(list)

    for model in all_models:
        models_by_type[model.cache_type].append(model)

    # Определение неиспользуемых моделей (старше 30 дней)
    current_time = time.time()
    thirty_days_ago = current_time - (30 * 24 * 60 * 60)
    unused_models = [
        model
        for model in all_models
        if model.last_accessed is not None and model.last_accessed < thirty_days_ago
    ]

    unused_size = sum(model.size_bytes for model in unused_models)

    return {
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
        "models": [model.to_dict() for model in sorted(all_models, key=lambda x: x.size_bytes, reverse=True)],
    }

