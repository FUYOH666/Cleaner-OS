"""Linux-specific platform helpers."""

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class LinuxDistro:
    """Linux distribution metadata."""

    name: str
    version: str
    id: str  # ubuntu, debian, fedora, arch, etc.


def detect_linux_distro() -> LinuxDistro | None:
    """Detect the Linux distribution.

    Checks standard files:
    - /etc/os-release (modern standard)
    - /etc/lsb-release (Ubuntu/Debian)
    - /etc/debian_version (Debian)
    - /etc/redhat-release (RHEL/CentOS)
    - /etc/arch-release (Arch)

    Returns:
        LinuxDistro if detected, otherwise None.
    """
    # Try /etc/os-release first (modern standard)
    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            os_release_data: dict[str, str] = {}
            with os_release.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        key, value = line.split("=", 1)
                        # Strip quotes from values
                        value = value.strip('"').strip("'")
                        os_release_data[key.lower()] = value

            name = os_release_data.get("name", "")
            version = os_release_data.get("version_id", os_release_data.get("version", ""))
            distro_id = os_release_data.get("id", "").lower()

            if name and distro_id:
                return LinuxDistro(name=name, version=version, id=distro_id)
        except Exception as e:
            logger.debug("Error reading /etc/os-release: %s", e)

    # Try /etc/lsb-release (Ubuntu/Debian)
    lsb_release = Path("/etc/lsb-release")
    if lsb_release.exists():
        try:
            lsb_data: dict[str, str] = {}
            with lsb_release.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        key, value = line.split("=", 1)
                        lsb_data[key.lower()] = value.strip('"').strip("'")

            distro_id = lsb_data.get("distrib_id", "").lower()
            version = lsb_data.get("distrib_release", "")
            name = lsb_data.get("distrib_description", distro_id)

            if distro_id:
                return LinuxDistro(name=name, version=version, id=distro_id)
        except Exception as e:
            logger.debug("Error reading /etc/lsb-release: %s", e)

    # Try /etc/debian_version (Debian)
    debian_version = Path("/etc/debian_version")
    if debian_version.exists():
        try:
            with debian_version.open(encoding="utf-8") as f:
                version = f.read().strip()
            return LinuxDistro(name="Debian", version=version, id="debian")
        except Exception as e:
            logger.debug("Error reading /etc/debian_version: %s", e)

    # Try /etc/redhat-release (RHEL/CentOS/Fedora)
    redhat_release = Path("/etc/redhat-release")
    if redhat_release.exists():
        try:
            with redhat_release.open(encoding="utf-8") as f:
                content = f.read().strip()
            # Parse content (e.g. "Fedora release 38 (Thirty Eight)")
            if "fedora" in content.lower():
                return LinuxDistro(name="Fedora", version="", id="fedora")
            elif "centos" in content.lower():
                return LinuxDistro(name="CentOS", version="", id="centos")
            elif "rhel" in content.lower() or "red hat" in content.lower():
                return LinuxDistro(name="Red Hat Enterprise Linux", version="", id="rhel")
            else:
                return LinuxDistro(name=content, version="", id="redhat")
        except Exception as e:
            logger.debug("Error reading /etc/redhat-release: %s", e)

    # Try /etc/arch-release (Arch Linux)
    arch_release = Path("/etc/arch-release")
    if arch_release.exists():
        return LinuxDistro(name="Arch Linux", version="", id="arch")

    logger.warning("Failed to detect Linux distribution")
    return None


def get_installed_packages() -> set[str]:
    """Return installed package names from the system package manager.

    Returns:
        Set of installed package names.
    """
    packages: set[str] = set()

    # Try common package managers
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
    """Return user-level systemd service names.

    Returns:
        List of systemd service names.
    """
    services: list[str] = []
    user_services_dir = Path.home() / ".config" / "systemd" / "user"

    if user_services_dir.exists():
        for service_file in user_services_dir.glob("*.service"):
            services.append(service_file.stem)

    return services


def get_flatpak_apps() -> set[str]:
    """Return installed Flatpak application names.

    Returns:
        Set of Flatpak application names.
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
            for line in result.stdout.splitlines()[1:]:  # Skip header
                parts = line.split()
                if parts:
                    apps.add(parts[0].split(".")[-1].lower())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return apps


def get_snap_apps() -> set[str]:
    """Return installed Snap application names.

    Returns:
        Set of Snap application names.
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
            for line in result.stdout.splitlines()[1:]:  # Skip header
                parts = line.split()
                if parts:
                    apps.add(parts[0].lower())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return apps
