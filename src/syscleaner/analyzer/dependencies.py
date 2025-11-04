"""Модуль анализа зависимостей Python."""

import logging
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def check_python_conflicts(project_path: Path) -> list[dict[str, Any]]:
    """
    Проверить конфликты зависимостей Python.

    Args:
        project_path: Путь к проекту с pyproject.toml или requirements.txt.

    Returns:
        Список найденных конфликтов.
    """
    conflicts: list[dict[str, Any]] = []

    # Проверяем наличие pyproject.toml или requirements.txt
    pyproject_toml = project_path / "pyproject.toml"
    requirements_txt = project_path / "requirements.txt"

    if not pyproject_toml.exists() and not requirements_txt.exists():
        return conflicts

    try:
        # Пробуем использовать uv pip check для проверки конфликтов
        result = subprocess.run(
            ["uv", "pip", "check"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0 and result.stdout:
            # Парсим вывод uv pip check
            for line in result.stdout.splitlines():
                if "has requirement" in line.lower() or "conflicts" in line.lower():
                    conflicts.append(
                        {
                            "project": str(project_path),
                            "message": line.strip(),
                            "severity": "warning",
                        },
                    )

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Не удалось проверить конфликты зависимостей: {e}")

    return conflicts


def find_unused_dependencies(project_path: Path) -> list[dict[str, Any]]:
    """
    Найти неиспользуемые зависимости в проекте.

    Args:
        project_path: Путь к проекту.

    Returns:
        Список потенциально неиспользуемых зависимостей.
    """
    unused: list[dict[str, Any]] = []

    # Простая проверка: ищем импорты в коде и сравниваем с зависимостями
    # Это базовая реализация, можно улучшить используя AST анализ

    pyproject_toml = project_path / "pyproject.toml"
    if not pyproject_toml.exists():
        return unused

    try:
        # Парсим pyproject.toml для получения зависимостей
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            import tomli as tomllib  # Python < 3.11

        with pyproject_toml.open("rb") as f:
            data = tomllib.load(f)

        dependencies = []
        if "project" in data and "dependencies" in data["project"]:
            dependencies = data["project"]["dependencies"]

        # Ищем все Python файлы в проекте
        python_files = list(project_path.rglob("*.py"))
        if not python_files:
            return unused

        # Собираем все импорты
        imports: set[str] = set()
        for py_file in python_files:
            try:
                content = py_file.read_text(encoding="utf-8")
                # Простой парсинг импортов (можно улучшить через AST)
                for line in content.splitlines():
                    if line.strip().startswith("import ") or line.strip().startswith("from "):
                        # Извлекаем имя модуля
                        import_part = line.strip().split()[1] if "import" in line else line.strip().split()[1]
                        module_name = import_part.split(".")[0]
                        imports.add(module_name)
            except Exception:
                continue

        # Сравниваем зависимости с импортами
        for dep in dependencies:
            # Извлекаем имя пакета из зависимости (может быть "package>=1.0.0")
            dep_name = dep.split(">=")[0].split("==")[0].split("@")[0].strip().split("[")[0]
            dep_name_normalized = dep_name.replace("-", "_").lower()

            # Проверяем, используется ли зависимость
            is_used = False
            for imp in imports:
                if imp.lower() == dep_name_normalized or imp.lower().startswith(dep_name_normalized):
                    is_used = True
                    break

            if not is_used:
                unused.append(
                    {
                        "project": str(project_path),
                        "dependency": dep_name,
                        "reason": "Не найдено использование в коде",
                    },
                )

    except Exception as e:
        logger.debug(f"Ошибка при поиске неиспользуемых зависимостей: {e}")

    return unused


def check_outdated_dependencies(project_path: Path) -> list[dict[str, Any]]:
    """
    Проверить устаревшие зависимости.

    Args:
        project_path: Путь к проекту.

    Returns:
        Список устаревших зависимостей.
    """
    outdated: list[dict[str, Any]] = []

    try:
        # Используем uv pip list для получения списка пакетов
        result = subprocess.run(
            ["uv", "pip", "list", "--outdated"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0 and result.stdout:
            lines = result.stdout.splitlines()
            # Пропускаем заголовок
            for line in lines[2:]:
                parts = line.split()
                if len(parts) >= 3:
                    outdated.append(
                        {
                            "project": str(project_path),
                            "package": parts[0],
                            "current": parts[1],
                            "latest": parts[2],
                        },
                    )

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Не удалось проверить устаревшие зависимости: {e}")

    return outdated


def analyze_python_dependencies(projects_dir: Path) -> dict[str, Any]:
    """
    Анализировать Python зависимости во всех проектах.

    Args:
        projects_dir: Директория с проектами.

    Returns:
        Словарь с результатами анализа.
    """
    all_conflicts: list[dict[str, Any]] = []
    all_unused: list[dict[str, Any]] = []
    all_outdated: list[dict[str, Any]] = []

    # Ищем все проекты с pyproject.toml или requirements.txt
    python_projects = []

    for project_path in projects_dir.iterdir():
        if project_path.is_dir():
            if (project_path / "pyproject.toml").exists() or (
                project_path / "requirements.txt"
            ).exists():
                python_projects.append(project_path)

    logger.info(f"Найдено {len(python_projects)} Python проектов")

    for project in python_projects:
        conflicts = check_python_conflicts(project)
        all_conflicts.extend(conflicts)

        unused = find_unused_dependencies(project)
        all_unused.extend(unused)

        outdated = check_outdated_dependencies(project)
        all_outdated.extend(outdated)

    return {
        "total_projects": len(python_projects),
        "conflicts": all_conflicts,
        "unused_dependencies": all_unused,
        "outdated_dependencies": all_outdated,
    }

