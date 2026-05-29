"""Python dependency analysis module."""

import logging
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def check_python_conflicts(project_path: Path) -> list[dict[str, Any]]:
    """Check Python dependency conflicts in a project.

    Args:
        project_path: Project root with pyproject.toml or requirements.txt.

    Returns:
        List of detected conflicts.
    """
    conflicts: list[dict[str, Any]] = []

    pyproject_toml = project_path / "pyproject.toml"
    requirements_txt = project_path / "requirements.txt"

    if not pyproject_toml.exists() and not requirements_txt.exists():
        return conflicts

    try:
        result = subprocess.run(
            ["uv", "pip", "check"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0 and result.stdout:
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
        logger.debug("Failed to check dependency conflicts: %s", e)

    return conflicts


def find_unused_dependencies(project_path: Path) -> list[dict[str, Any]]:
    """Find dependencies that may be unused in project code.

    Args:
        project_path: Project root.

    Returns:
        List of potentially unused dependencies.
    """
    unused: list[dict[str, Any]] = []

    # Basic import scan; can be improved with AST analysis

    pyproject_toml = project_path / "pyproject.toml"
    if not pyproject_toml.exists():
        return unused

    try:
        import tomllib

        with pyproject_toml.open("rb") as f:
            data = tomllib.load(f)

        dependencies = []
        if "project" in data and "dependencies" in data["project"]:
            dependencies = data["project"]["dependencies"]

        python_files = list(project_path.rglob("*.py"))
        if not python_files:
            return unused

        imports: set[str] = set()
        for py_file in python_files:
            try:
                content = py_file.read_text(encoding="utf-8")
                for line in content.splitlines():
                    if line.strip().startswith("import ") or line.strip().startswith("from "):
                        parts = line.strip().split()
                        import_part = parts[1] if len(parts) > 1 else ""
                        module_name = import_part.split(".")[0]
                        imports.add(module_name)
            except Exception:
                continue

        for dep in dependencies:
            dep_name = dep.split(">=")[0].split("==")[0].split("@")[0].strip().split("[")[0]
            dep_name_normalized = dep_name.replace("-", "_").lower()

            is_used = False
            for imp in imports:
                imp_lower = imp.lower()
                if imp_lower == dep_name_normalized or imp_lower.startswith(dep_name_normalized):
                    is_used = True
                    break

            if not is_used:
                unused.append(
                    {
                        "project": str(project_path),
                        "dependency": dep_name,
                        "reason": "No usage found in code",
                    },
                )

    except Exception as e:
        logger.debug("Error finding unused dependencies: %s", e)

    return unused


def check_outdated_dependencies(project_path: Path) -> list[dict[str, Any]]:
    """Check for outdated Python dependencies.

    Args:
        project_path: Project root.

    Returns:
        List of outdated packages.
    """
    outdated: list[dict[str, Any]] = []

    try:
        result = subprocess.run(
            ["uv", "pip", "list", "--outdated"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0 and result.stdout:
            lines = result.stdout.splitlines()
            for line in lines[2:]:  # Skip header
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
        logger.debug("Failed to check outdated dependencies: %s", e)

    return outdated


def analyze_python_dependencies(projects_dirs: list[Path]) -> dict[str, Any]:
    """Analyze Python dependencies across project directories.

    Args:
        projects_dirs: Directories containing projects.

    Returns:
        Aggregated dependency analysis results.
    """
    all_conflicts: list[dict[str, Any]] = []
    all_unused: list[dict[str, Any]] = []
    all_outdated: list[dict[str, Any]] = []
    python_projects: list[Path] = []

    for projects_dir in projects_dirs:
        if not projects_dir.exists() or not projects_dir.is_dir():
            continue

        try:
            for project_path in projects_dir.iterdir():
                if project_path.is_dir():
                    if (project_path / "pyproject.toml").exists() or (
                        project_path / "requirements.txt"
                    ).exists():
                        python_projects.append(project_path)
        except Exception as e:
            logger.debug("Error scanning %s: %s", projects_dir, e)

    logger.info("Found %d Python projects", len(python_projects))

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
