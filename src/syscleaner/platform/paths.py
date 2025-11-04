"""Модуль платформо-независимых путей."""

import logging
from pathlib import Path

from syscleaner.platform.detector import IS_LINUX, IS_MACOS, Platform

logger = logging.getLogger(__name__)


class PlatformPaths:
    """Класс для получения платформо-независимых путей."""

    def __init__(self, home: Path | None = None) -> None:
        """
        Инициализация путей.

        Args:
            home: Домашняя директория пользователя. Если None, используется Path.home().
        """
        self.home = home or Path.home()
        self.platform = Platform.MACOS if IS_MACOS else Platform.LINUX

    def cache_dir(self) -> Path:
        """
        Получить директорию кэшей.

        Returns:
            Путь к директории кэшей.
        """
        if IS_MACOS:
            return self.home / "Library" / "Caches"
        elif IS_LINUX:
            return self.home / ".cache"
        else:
            # Fallback для неизвестных платформ
            return self.home / ".cache"

    def app_support_dir(self) -> Path:
        """
        Получить директорию поддержки приложений.

        Returns:
            Путь к директории поддержки приложений.
        """
        if IS_MACOS:
            return self.home / "Library" / "Application Support"
        elif IS_LINUX:
            return self.home / ".local" / "share"
        else:
            return self.home / ".local" / "share"

    def logs_dir(self) -> Path:
        """
        Получить директорию логов.

        Returns:
            Путь к директории логов.
        """
        if IS_MACOS:
            return self.home / "Library" / "Logs"
        elif IS_LINUX:
            return self.home / ".local" / "share" / "logs"
        else:
            return self.home / ".local" / "share" / "logs"

    def ssh_dir(self) -> Path:
        """
        Получить директорию SSH.

        Returns:
            Путь к директории SSH.
        """
        return self.home / ".ssh"

    def trash_dir(self) -> Path:
        """
        Получить директорию корзины.

        Returns:
            Путь к директории корзины.
        """
        if IS_MACOS:
            return self.home / ".Trash"
        elif IS_LINUX:
            # Разные дистрибутивы используют разные пути
            # Попробуем стандартные варианты
            trash = self.home / ".local" / "share" / "Trash"
            if trash.exists():
                return trash
            # Альтернативный вариант
            return self.home / ".Trash"
        else:
            return self.home / ".Trash"

    def applications_dir(self) -> Path | None:
        """
        Получить директорию приложений (только для macOS).

        Returns:
            Путь к директории приложений или None для Linux.
        """
        if IS_MACOS:
            return Path("/Applications")
        else:
            return None

    def ml_cache_dirs(self) -> list[Path]:
        """
        Получить директории кэша ML моделей.

        Returns:
            Список путей к директориям кэша ML моделей.
        """
        cache_base = self.cache_dir()
        ml_dirs = []

        # Hugging Face cache
        hf_cache = cache_base / "huggingface"
        if hf_cache.exists():
            ml_dirs.append(hf_cache)

        # PyTorch cache
        torch_cache = cache_base / "torch"
        if torch_cache.exists():
            ml_dirs.append(torch_cache)

        # TensorFlow cache
        tf_cache = cache_base / "tensorflow"
        if tf_cache.exists():
            ml_dirs.append(tf_cache)

        # ONNX cache
        onnx_cache = cache_base / "onnx"
        if onnx_cache.exists():
            ml_dirs.append(onnx_cache)

        # Keras cache (может быть в home)
        keras_cache = self.home / ".keras"
        if keras_cache.exists():
            ml_dirs.append(keras_cache)

        # Hugging Face может быть в разных местах
        if IS_MACOS:
            hf_macos_cache = self.home / "Library" / "Caches" / "huggingface"
            if hf_macos_cache.exists() and hf_macos_cache not in ml_dirs:
                ml_dirs.append(hf_macos_cache)

        return ml_dirs

    def temp_dir(self) -> Path:
        """
        Получить временную директорию.

        Returns:
            Путь к временной директории.
        """
        import tempfile

        return Path(tempfile.gettempdir())

    def config_dirs(self) -> list[Path]:
        """
        Получить директории конфигурации.

        Returns:
            Список путей к директориям конфигурации.
        """
        if IS_MACOS:
            return [self.home / "Library" / "Preferences"]
        elif IS_LINUX:
            return [self.home / ".config"]
        else:
            return [self.home / ".config"]

    def find_project_directories(self, max_depth: int = 3) -> list[Path]:
        """
        Найти директории проектов разработки в стандартных местах.

        Ищет git репозитории или проекты с pyproject.toml/requirements.txt в:
        - ~/development/
        - ~/dev/
        - ~/projects/
        - ~/code/
        - ~/workspace/
        - ~/Documents/Projects/
        - ~/Documents/Code/

        Args:
            max_depth: Максимальная глубина поиска в стандартных директориях.

        Returns:
            Список путей к найденным директориям проектов.
        """
        project_dirs: list[Path] = []
        found_paths: set[Path] = set()

        # Стандартные места для поиска
        search_locations = [
            self.home / "development",
            self.home / "dev",
            self.home / "projects",
            self.home / "code",
            self.home / "workspace",
            self.home / "Documents" / "Projects",
            self.home / "Documents" / "Code",
        ]

        def is_project_directory(path: Path) -> bool:
            """Проверить, является ли директория проектом разработки."""
            if not path.is_dir():
                return False

            # Проверяем наличие признаков проекта
            project_indicators = [
                path / ".git",  # Git репозиторий
                path / "pyproject.toml",  # Python проект
                path / "requirements.txt",  # Python зависимости
                path / "package.json",  # Node.js проект
                path / "Cargo.toml",  # Rust проект
                path / "go.mod",  # Go проект
            ]

            return any(indicator.exists() for indicator in project_indicators)

        def find_projects_in_directory(base_dir: Path, depth: int = 0) -> None:
            """Рекурсивно найти проекты в директории."""
            if depth > max_depth or not base_dir.exists():
                return

            try:
                # Проверяем саму директорию
                if is_project_directory(base_dir):
                    if base_dir not in found_paths:
                        project_dirs.append(base_dir)
                        found_paths.add(base_dir)
                    return  # Не ищем внутри проекта

                # Ищем поддиректории с проектами
                try:
                    for item in base_dir.iterdir():
                        if item.is_dir() and not item.name.startswith("."):
                            find_projects_in_directory(item, depth + 1)
                except PermissionError:
                    logger.debug(f"Нет доступа к {base_dir}")
                except Exception as e:
                    logger.debug(f"Ошибка при сканировании {base_dir}: {e}")

            except Exception as e:
                logger.debug(f"Ошибка при проверке {base_dir}: {e}")

        # Ищем проекты в стандартных местах
        for search_location in search_locations:
            if search_location.exists():
                logger.debug(f"Поиск проектов в {search_location}")
                find_projects_in_directory(search_location)

        # Также проверяем, есть ли проекты прямо в домашней директории
        # (но только на первом уровне, чтобы не было слишком медленно)
        try:
            for item in self.home.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    if is_project_directory(item):
                        if item not in found_paths:
                            project_dirs.append(item)
                            found_paths.add(item)
        except Exception as e:
            logger.debug(f"Ошибка при проверке домашней директории: {e}")

        logger.info(f"Найдено {len(project_dirs)} директорий проектов")
        return project_dirs

