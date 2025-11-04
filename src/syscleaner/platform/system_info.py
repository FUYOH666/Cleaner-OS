"""Модуль определения системной информации (железо, диск)."""

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from syscleaner.platform.detector import IS_LINUX, IS_MACOS

logger = logging.getLogger(__name__)


@dataclass
class GPUInfo:
    """Информация о GPU."""

    has_gpu: bool
    gpu_type: str | None = None  # NVIDIA, AMD, Intel, Metal
    gpu_model: str | None = None
    details: str | None = None


@dataclass
class DiskInfo:
    """Информация о диске."""

    total_gb: float
    used_gb: float
    free_gb: float
    usage_percent: float


def format_size_gb(size_bytes: int) -> float:
    """
    Преобразовать размер в байтах в гигабайты.

    Args:
        size_bytes: Размер в байтах.

    Returns:
        Размер в гигабайтах.
    """
    return size_bytes / (1024**3)


def detect_gpu() -> GPUInfo:
    """
    Определить наличие и тип GPU.

    Returns:
        GPUInfo с информацией о GPU.
    """
    if IS_MACOS:
        return _detect_gpu_macos()
    elif IS_LINUX:
        return _detect_gpu_linux()
    else:
        return GPUInfo(has_gpu=False)


def _detect_gpu_macos() -> GPUInfo:
    """Определить GPU на macOS."""
    # Проверяем наличие Metal (macOS GPU API)
    try:
        result = subprocess.run(
            ["system_profiler", "SPDisplaysDataType"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            output = result.stdout.lower()
            if "chipset model" in output or "displays" in output:
                # Парсим модель GPU
                lines = result.stdout.splitlines()
                gpu_model = None
                for i, line in enumerate(lines):
                    if "chipset model" in line.lower():
                        parts = line.split(":")
                        if len(parts) > 1:
                            gpu_model = parts[1].strip()
                            break

                return GPUInfo(
                    has_gpu=True,
                    gpu_type="Metal",
                    gpu_model=gpu_model or "Unknown",
                    details=result.stdout[:200],  # Первые 200 символов
                )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Не удалось определить GPU через system_profiler: {e}")

    # Fallback: проверяем наличие Metal через другие методы
    try:
        # Проверяем наличие Metal фреймворка
        metal_framework = Path("/System/Library/Frameworks/Metal.framework")
        if metal_framework.exists():
            return GPUInfo(has_gpu=True, gpu_type="Metal")
    except Exception as e:
        logger.debug(f"Ошибка при проверке Metal: {e}")

    return GPUInfo(has_gpu=False)


def _detect_gpu_linux() -> GPUInfo:
    """Определить GPU на Linux."""
    # Проверяем NVIDIA через nvidia-smi
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            gpu_model = result.stdout.strip().split("\n")[0] if result.stdout.strip() else None
            return GPUInfo(
                has_gpu=True,
                gpu_type="NVIDIA",
                gpu_model=gpu_model or "Unknown",
            )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Проверяем наличие NVIDIA драйвера
    nvidia_driver = Path("/proc/driver/nvidia")
    if nvidia_driver.exists():
        return GPUInfo(has_gpu=True, gpu_type="NVIDIA")

    # Проверяем через lspci
    try:
        result = subprocess.run(
            ["lspci"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            output = result.stdout.lower()
            if "nvidia" in output:
                return GPUInfo(has_gpu=True, gpu_type="NVIDIA")
            elif "amd" in output and ("vga" in output or "display" in output):
                return GPUInfo(has_gpu=True, gpu_type="AMD")
            elif "intel" in output and ("vga" in output or "display" in output):
                return GPUInfo(has_gpu=True, gpu_type="Intel")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Проверяем через /proc/driver
    try:
        if Path("/proc/driver/radeon").exists():
            return GPUInfo(has_gpu=True, gpu_type="AMD")
        elif Path("/proc/driver/i915").exists():  # Intel
            return GPUInfo(has_gpu=True, gpu_type="Intel")
    except Exception:
        pass

    return GPUInfo(has_gpu=False)


def get_disk_info(path: Path | None = None) -> DiskInfo | None:
    """
    Получить информацию о диске.

    Args:
        path: Путь для проверки диска. Если None, используется корневая директория.

    Returns:
        DiskInfo с информацией о диске или None если не удалось получить информацию.
    """
    if path is None:
        path = Path("/")

    try:
        usage = shutil.disk_usage(path)

        total_gb = format_size_gb(usage.total)
        used_gb = format_size_gb(usage.used)
        free_gb = format_size_gb(usage.free)

        usage_percent = (used_gb / total_gb) * 100 if total_gb > 0 else 0

        return DiskInfo(
            total_gb=total_gb,
            used_gb=used_gb,
            free_gb=free_gb,
            usage_percent=usage_percent,
        )
    except Exception as e:
        logger.debug(f"Ошибка при получении информации о диске: {e}")
        return None


def get_home_disk_info() -> DiskInfo | None:
    """
    Получить информацию о диске домашней директории.

    Returns:
        DiskInfo с информацией о диске домашней директории.
    """
    home = Path.home()
    return get_disk_info(home)

