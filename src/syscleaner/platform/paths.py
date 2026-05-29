"""Cross-platform path resolution module."""

import logging
from pathlib import Path

from syscleaner.platform.detector import IS_LINUX, IS_MACOS, Platform

logger = logging.getLogger(__name__)


class PlatformPaths:
    """Cross-platform path helpers."""

    def __init__(self, home: Path | None = None) -> None:
        """Initialize paths.

        Args:
            home: User home directory. Defaults to Path.home().
        """
        self.home = home or Path.home()
        self.platform = Platform.MACOS if IS_MACOS else Platform.LINUX

    def cache_dir(self) -> Path:
        """Return the cache directory path.

        Returns:
            Path to the cache directory.
        """
        if IS_MACOS:
            return self.home / "Library" / "Caches"
        elif IS_LINUX:
            return self.home / ".cache"
        else:
            # Fallback for unknown platforms
            return self.home / ".cache"

    def app_support_dir(self) -> Path:
        """Return the application support directory path.

        Returns:
            Path to application support data.
        """
        if IS_MACOS:
            return self.home / "Library" / "Application Support"
        elif IS_LINUX:
            return self.home / ".local" / "share"
        else:
            return self.home / ".local" / "share"

    def logs_dir(self) -> Path:
        """Return the logs directory path.

        Returns:
            Path to the logs directory.
        """
        if IS_MACOS:
            return self.home / "Library" / "Logs"
        elif IS_LINUX:
            return self.home / ".local" / "share" / "logs"
        else:
            return self.home / ".local" / "share" / "logs"

    def ssh_dir(self) -> Path:
        """Return the SSH directory path.

        Returns:
            Path to the SSH directory.
        """
        return self.home / ".ssh"

    def trash_dir(self) -> Path:
        """Return the trash directory path.

        Returns:
            Path to the trash directory.
        """
        if IS_MACOS:
            return self.home / ".Trash"
        elif IS_LINUX:
            # Distributions may use different trash locations
            trash = self.home / ".local" / "share" / "Trash"
            if trash.exists():
                return trash
            # Alternative location
            return self.home / ".Trash"
        else:
            return self.home / ".Trash"

    def applications_dir(self) -> Path | None:
        """Return the applications directory path (macOS only).

        Returns:
            Path to /Applications on macOS, None on Linux.
        """
        if IS_MACOS:
            return Path("/Applications")
        else:
            return None

    def ml_cache_dirs(self) -> list[Path]:
        """Return ML model cache directory paths.

        Returns:
            List of existing ML cache directories.
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

        # Keras cache (may live under home)
        keras_cache = self.home / ".keras"
        if keras_cache.exists():
            ml_dirs.append(keras_cache)

        # Hugging Face may also use a macOS-specific cache path
        if IS_MACOS:
            hf_macos_cache = self.home / "Library" / "Caches" / "huggingface"
            if hf_macos_cache.exists() and hf_macos_cache not in ml_dirs:
                ml_dirs.append(hf_macos_cache)

        return ml_dirs

    def temp_dir(self) -> Path:
        """Return the system temporary directory path.

        Returns:
            Path to the temporary directory.
        """
        import tempfile

        return Path(tempfile.gettempdir())

    def config_dirs(self) -> list[Path]:
        """Return configuration directory paths.

        Returns:
            List of configuration directory paths.
        """
        if IS_MACOS:
            return [self.home / "Library" / "Preferences"]
        elif IS_LINUX:
            return [self.home / ".config"]
        else:
            return [self.home / ".config"]

    def find_project_directories(self, max_depth: int = 3) -> list[Path]:
        """Find development project directories in common locations.

        Looks for git repos or projects with pyproject.toml/requirements.txt in:
        - ~/development/
        - ~/dev/
        - ~/projects/
        - ~/code/
        - ~/workspace/
        - ~/Documents/Projects/
        - ~/Documents/Code/

        Args:
            max_depth: Maximum search depth under each standard directory.

        Returns:
            List of discovered project directory paths.
        """
        project_dirs: list[Path] = []
        found_paths: set[Path] = set()

        # Standard search locations
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
            """Return True if the path looks like a development project."""
            if not path.is_dir():
                return False

            # Project indicators
            project_indicators = [
                path / ".git",  # Git repository
                path / "pyproject.toml",  # Python project
                path / "requirements.txt",  # Python dependencies
                path / "package.json",  # Node.js project
                path / "Cargo.toml",  # Rust project
                path / "go.mod",  # Go project
            ]

            return any(indicator.exists() for indicator in project_indicators)

        def find_projects_in_directory(base_dir: Path, depth: int = 0) -> None:
            """Recursively find projects under base_dir."""
            if depth > max_depth or not base_dir.exists():
                return

            try:
                # Check base_dir itself
                if is_project_directory(base_dir):
                    if base_dir not in found_paths:
                        project_dirs.append(base_dir)
                        found_paths.add(base_dir)
                    return  # Do not search inside a project root

                # Search subdirectories
                try:
                    for item in base_dir.iterdir():
                        if item.is_dir() and not item.name.startswith("."):
                            find_projects_in_directory(item, depth + 1)
                except PermissionError:
                    logger.debug("No access to %s", base_dir)
                except Exception as e:
                    logger.debug("Error scanning %s: %s", base_dir, e)

            except Exception as e:
                logger.debug("Error checking %s: %s", base_dir, e)

        # Search standard locations
        for search_location in search_locations:
            if search_location.exists():
                logger.debug("Searching for projects in %s", search_location)
                find_projects_in_directory(search_location)

        # Also check top-level home directories (depth 1 only)
        try:
            for item in self.home.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    if is_project_directory(item):
                        if item not in found_paths:
                            project_dirs.append(item)
                            found_paths.add(item)
        except Exception as e:
            logger.debug("Error checking home directory: %s", e)

        logger.info("Found %d project directories", len(project_dirs))
        return project_dirs
