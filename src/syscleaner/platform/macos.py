"""Платформо-специфичные функции для macOS."""

from pathlib import Path


def get_installed_apps() -> set[str]:
    """
    Получить список установленных приложений macOS.

    Returns:
        Множество имен установленных приложений (без .app расширения).
    """
    apps_dir = Path("/Applications")
    installed_apps: set[str] = set()

    if apps_dir.exists():
        for app in apps_dir.glob("*.app"):
            installed_apps.add(app.stem.lower())

    return installed_apps


def get_launch_agents_paths() -> list[Path]:
    """
    Получить пути к LaunchAgents и LaunchDaemons.

    Returns:
        Список путей к директориям LaunchAgents и LaunchDaemons.
    """
    home = Path.home()
    paths = [
        home / "Library" / "LaunchAgents",
        Path("/Library") / "LaunchAgents",
        Path("/Library") / "LaunchDaemons",
        Path("/System") / "Library" / "LaunchAgents",
        Path("/System") / "Library" / "LaunchDaemons",
    ]
    return [p for p in paths if p.exists()]

