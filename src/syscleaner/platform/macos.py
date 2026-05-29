"""macOS-specific platform helpers."""

from pathlib import Path


def get_installed_apps() -> set[str]:
    """Return installed macOS application names.

    Returns:
        Set of application names (without the .app extension).
    """
    apps_dir = Path("/Applications")
    installed_apps: set[str] = set()

    if apps_dir.exists():
        for app in apps_dir.glob("*.app"):
            installed_apps.add(app.stem.lower())

    return installed_apps


def get_launch_agents_paths() -> list[Path]:
    """Return LaunchAgents and LaunchDaemons directory paths.

    Returns:
        List of existing LaunchAgents and LaunchDaemons paths.
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
