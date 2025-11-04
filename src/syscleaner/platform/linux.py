"""Платформо-специфичные функции для Linux."""

import subprocess
from pathlib import Path


def get_installed_packages() -> set[str]:
    """
    Получить список установленных пакетов через package manager.

    Returns:
        Множество имен установленных пакетов.
    """
    packages: set[str] = set()

    # Пробуем разные package managers
    package_managers = [
        ("dpkg", ["-l"], lambda line: line.split()[1] if len(line.split()) > 1 else None),
        ("rpm", ["-qa"], lambda line: line.strip()),
        ("pacman", ["-Q"], lambda line: line.split()[0] if line.split() else None),
    ]

    for cmd, args, parser in package_managers:
        try:
            result = subprocess.run(
                [cmd] + args,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    package = parser(line)
                    if package:
                        packages.add(package.lower())
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return packages


def get_systemd_services() -> list[str]:
    """
    Получить список systemd сервисов пользователя.

    Returns:
        Список имен systemd сервисов.
    """
    services: list[str] = []
    user_services_dir = Path.home() / ".config" / "systemd" / "user"

    if user_services_dir.exists():
        for service_file in user_services_dir.glob("*.service"):
            services.append(service_file.stem)

    return services


def get_flatpak_apps() -> set[str]:
    """
    Получить список установленных Flatpak приложений.

    Returns:
        Множество имен Flatpak приложений.
    """
    apps: set[str] = set()

    try:
        result = subprocess.run(
            ["flatpak", "list", "--app"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines()[1:]:  # Пропускаем заголовок
                parts = line.split()
                if parts:
                    apps.add(parts[0].split(".")[-1].lower())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return apps


def get_snap_apps() -> set[str]:
    """
    Получить список установленных Snap приложений.

    Returns:
        Множество имен Snap приложений.
    """
    apps: set[str] = set()

    try:
        result = subprocess.run(
            ["snap", "list"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines()[1:]:  # Пропускаем заголовок
                parts = line.split()
                if parts:
                    apps.add(parts[0].lower())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return apps

