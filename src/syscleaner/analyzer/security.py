"""Модуль проверки безопасности (кроссплатформенный)."""

import logging
import stat
from pathlib import Path
from typing import Any

from syscleaner.platform.paths import PlatformPaths

logger = logging.getLogger(__name__)


class SecurityIssue:
    """Проблема безопасности."""

    def __init__(
        self,
        severity: str,
        category: str,
        path: str,
        description: str,
        recommendation: str | None = None,
    ) -> None:
        """
        Инициализация проблемы безопасности.

        Args:
            severity: Уровень серьезности (high, medium, low).
            category: Категория проблемы.
            path: Путь к проблемному файлу/директории.
            description: Описание проблемы.
            recommendation: Рекомендация по исправлению.
        """
        self.severity = severity
        self.category = category
        self.path = path
        self.description = description
        self.recommendation = recommendation


def check_ssh_permissions(paths: PlatformPaths) -> list[SecurityIssue]:
    """
    Проверить права доступа SSH ключей.

    Args:
        paths: Объект PlatformPaths для получения путей.

    Returns:
        Список найденных проблем безопасности.
    """
    issues: list[SecurityIssue] = []
    ssh_dir = paths.ssh_dir()

    if not ssh_dir.exists():
        logger.info(f"SSH директория не найдена: {ssh_dir}")
        return issues

    # Проверяем права на саму директорию
    try:
        dir_stat = ssh_dir.stat()
        dir_mode = stat.filemode(dir_stat.st_mode)
        if dir_mode != "drwx------":
            issues.append(
                SecurityIssue(
                    severity="high",
                    category="ssh_permissions",
                    path=str(ssh_dir),
                    description=f"Неправильные права на директорию .ssh: {dir_mode} (должно быть drwx------)",
                    recommendation="Выполните: chmod 700 ~/.ssh",
                ),
            )
    except OSError as e:
        logger.error(f"Ошибка при проверке прав на .ssh: {e}")
        return issues

    # Проверяем приватные ключи
    private_key_patterns = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]
    for key_file in ssh_dir.iterdir():
        if key_file.is_file() and any(key_file.name == pattern for pattern in private_key_patterns):
            try:
                file_stat = key_file.stat()
                file_mode = stat.filemode(file_stat.st_mode)
                # Приватные ключи должны быть -rw------- (600)
                if file_mode != "-rw-------":
                    issues.append(
                        SecurityIssue(
                            severity="high",
                            category="ssh_permissions",
                            path=str(key_file),
                            description=f"Неправильные права на приватный ключ: {file_mode} (должно быть -rw-------)",
                            recommendation=f"Выполните: chmod 600 {key_file}",
                        ),
                    )
            except OSError as e:
                logger.error(f"Ошибка при проверке прав на ключ {key_file}: {e}")

    return issues


def check_file_permissions(file_path: Path) -> SecurityIssue | None:
    """
    Проверить права доступа на файл.

    Args:
        file_path: Путь к файлу.

    Returns:
        SecurityIssue если найдена проблема, иначе None.
    """
    try:
        file_stat = file_path.stat()
        file_mode = stat.filemode(file_stat.st_mode)

        # Проверяем, доступен ли файл для чтения всем (world-readable)
        if file_stat.st_mode & stat.S_IROTH:
            # Проверяем, содержит ли файл секреты (по расширению или имени)
            sensitive_extensions = [".env", ".key", ".pem", ".p12", ".pfx"]
            sensitive_names = ["secret", "password", "credential", "token", "api_key"]

            file_name_lower = file_path.name.lower()
            is_sensitive = (
                any(file_name_lower.endswith(ext) for ext in sensitive_extensions)
                or any(name in file_name_lower for name in sensitive_names)
            )

            if is_sensitive:
                return SecurityIssue(
                    severity="high",
                    category="file_permissions",
                    path=str(file_path),
                    description=f"Секретный файл доступен для чтения всем: {file_mode}",
                    recommendation=f"Выполните: chmod 600 {file_path}",
                )
    except OSError:
        pass

    return None


def find_sensitive_files(
    search_paths: list[Path],
    patterns: list[str],
) -> list[dict[str, Any]]:
    """
    Найти файлы с секретами по паттернам.

    Args:
        search_paths: Список путей для поиска.
        patterns: Список паттернов для поиска (например, ["*.env", "*secret*"]).

    Returns:
        Список найденных файлов с секретами.
    """
    found_files: list[dict[str, Any]] = []

    for search_path in search_paths:
        if not search_path.exists():
            continue

        try:
            for pattern in patterns:
                # Используем rglob для рекурсивного поиска
                for file_path in search_path.rglob(pattern):
                    if file_path.is_file():
                        try:
                            size = file_path.stat().st_size
                            found_files.append(
                                {
                                    "path": str(file_path),
                                    "pattern": pattern,
                                    "size_bytes": size,
                                },
                            )
                        except (OSError, PermissionError):
                            continue
        except Exception as e:
            logger.debug(f"Нет доступа к {search_path}: {e}")

    return found_files


def scan_security(
    paths: PlatformPaths,
    check_ssh: bool = True,
    check_permissions: bool = True,
    sensitive_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """
    Выполнить полное сканирование безопасности.

    Args:
        paths: Объект PlatformPaths для получения путей.
        check_ssh: Проверять SSH ключи.
        check_permissions: Проверять права доступа файлов.
        sensitive_patterns: Паттерны для поиска чувствительных файлов.

    Returns:
        Словарь с результатами сканирования безопасности.
    """
    issues: list[SecurityIssue] = []
    sensitive_files: list[dict[str, Any]] = []

    if check_ssh:
        ssh_issues = check_ssh_permissions(paths)
        issues.extend(ssh_issues)

    if sensitive_patterns:
        search_paths = [paths.home, paths.home / "development", paths.home / "Documents"]
        sensitive_files = find_sensitive_files(search_paths, sensitive_patterns)

        # Проверяем права доступа на найденные файлы
        if check_permissions:
            for file_info in sensitive_files:
                file_path = Path(file_info["path"])
                perm_issue = check_file_permissions(file_path)
                if perm_issue:
                    issues.append(perm_issue)

    # Конвертируем SecurityIssue в словари для сериализации
    issues_dict = [
        {
            "severity": issue.severity,
            "category": issue.category,
            "path": issue.path,
            "description": issue.description,
            "recommendation": issue.recommendation,
        }
        for issue in issues
    ]

    return {
        "issues": issues_dict,
        "sensitive_files": sensitive_files,
        "total_issues": len(issues_dict),
        "high_severity_issues": len([i for i in issues_dict if i["severity"] == "high"]),
    }

