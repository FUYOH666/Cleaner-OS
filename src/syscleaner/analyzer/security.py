"""Cross-platform security check module."""

import logging
import stat
from pathlib import Path
from typing import Any

from syscleaner.platform.paths import PlatformPaths

logger = logging.getLogger(__name__)


def _should_ignore_file(file_path: Path) -> bool:
    """Return True if the file should be skipped during security checks.

    Ignores:
    - Files under node_modules, dist, build, .venv, venv
    - Type stubs (.pyi files)
    - Editor extension trees (.cursor/extensions, .vscode/extensions)
    - Library cache dirs (Library/Caches/, .cache/)
    - System application directories
    - Standard Python library paths (site-packages, lib/python3.*/)
    - Installer-managed paths (uv, conda, pip)

    Args:
        file_path: Path to the file.

    Returns:
        True if the file should be ignored.
    """
    path_str = str(file_path)
    parts = path_str.split("/")

    # Build artifacts and dependency trees
    ignore_dir_names = {
        "node_modules",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "egg-info",
        "site-packages",
        ".cache",
    }

    # Editor extensions
    if ".cursor/extensions" in path_str or ".vscode/extensions" in path_str:
        return True

    # Application caches (Cypress, libraries, etc.)
    if "/Library/Caches/" in path_str:
        return True

    # Installer-managed directories
    if "/.local/share/uv/" in path_str or "/.local/share/pip/" in path_str:
        return True
    if "/conda/" in path_str and ("site-packages" in path_str or "lib/python" in path_str):
        return True

    # Standard Python library trees
    if "lib/python" in path_str and ("site-packages" in path_str or "dist-packages" in path_str):
        return True

    # Library documentation
    if "/docs/" in path_str.lower() or "/documentation/" in path_str.lower():
        return True

    # Installed packages (secrets.py, credentials.py from third-party libs)
    if "site-packages" in path_str or "dist-packages" in path_str:
        return True

    # Type stubs are not runtime secret carriers
    if file_path.suffix == ".pyi":
        return True

    # C/C++ headers are not secrets
    if file_path.suffix in {".h", ".hpp", ".hxx"}:
        return True

    # Do not ignore .env at project roots via generic dir names
    for part in parts:
        if part in ignore_dir_names:
            return True

    return False


class SecurityIssue:
    """A security finding."""

    def __init__(
        self,
        severity: str,
        category: str,
        path: str,
        description: str,
        recommendation: str | None = None,
    ) -> None:
        """Initialize a security issue.

        Args:
            severity: Severity level (high, medium, low).
            category: Issue category.
            path: Path to the affected file or directory.
            description: Issue description.
            recommendation: Optional remediation guidance.
        """
        self.severity = severity
        self.category = category
        self.path = path
        self.description = description
        self.recommendation = recommendation


def check_ssh_permissions(paths: PlatformPaths) -> list[SecurityIssue]:
    """Check SSH key and .ssh directory permissions.

    Args:
        paths: PlatformPaths instance for resolving paths.

    Returns:
        List of security issues.
    """
    issues: list[SecurityIssue] = []
    ssh_dir = paths.ssh_dir()

    if not ssh_dir.exists():
        logger.info("SSH directory not found: %s", ssh_dir)
        return issues

    # Check .ssh directory permissions
    try:
        dir_stat = ssh_dir.stat()
        dir_mode = stat.filemode(dir_stat.st_mode)
        if dir_mode != "drwx------":
            issues.append(
                SecurityIssue(
                    severity="high",
                    category="ssh_permissions",
                    path=str(ssh_dir),
                    description=f"Wrong .ssh dir permissions: {dir_mode} (expected drwx------)",
                    recommendation="Run: chmod 700 ~/.ssh",
                ),
            )
    except OSError as e:
        logger.error("Error checking .ssh permissions: %s", e)
        return issues

    # Check private keys
    private_key_patterns = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]
    for key_file in ssh_dir.iterdir():
        if key_file.is_file() and any(key_file.name == pattern for pattern in private_key_patterns):
            try:
                file_stat = key_file.stat()
                file_mode = stat.filemode(file_stat.st_mode)
                # Private keys must be -rw------- (600)
                if file_mode != "-rw-------":
                    issues.append(
                        SecurityIssue(
                            severity="high",
                            category="ssh_permissions",
                            path=str(key_file),
                            description=f"Wrong key perms: {file_mode} (expected -rw-------)",
                            recommendation=f"Run: chmod 600 {key_file}",
                        ),
                    )
            except OSError as e:
                logger.error("Error checking key permissions for %s: %s", key_file, e)

    return issues


def check_file_permissions(file_path: Path) -> SecurityIssue | None:
    """Check file permissions for overly permissive sensitive files.

    Args:
        file_path: Path to the file.

    Returns:
        SecurityIssue if a problem is found, otherwise None.
    """
    # Skip build artifacts, extensions, and type stubs
    if _should_ignore_file(file_path):
        return None

    try:
        file_stat = file_path.stat()
        file_mode = stat.filemode(file_stat.st_mode)

        # World-readable sensitive files
        if file_stat.st_mode & stat.S_IROTH:
            sensitive_extensions = [".env", ".key", ".pem", ".p12", ".pfx"]
            sensitive_names = ["secret", "password", "credential", "token", "api_key"]

            file_name_lower = file_path.name.lower()
            is_sensitive = any(
                file_name_lower.endswith(ext) for ext in sensitive_extensions
            ) or any(name in file_name_lower for name in sensitive_names)

            if is_sensitive:
                return SecurityIssue(
                    severity="high",
                    category="file_permissions",
                    path=str(file_path),
                    description=f"Sensitive file world-readable: {file_mode}",
                    recommendation=f"Run: chmod 600 {file_path}",
                )
    except OSError:
        pass

    return None


def find_sensitive_files(
    search_paths: list[Path],
    patterns: list[str],
) -> list[dict[str, Any]]:
    """Find files matching sensitive-name patterns.

    Args:
        search_paths: Directories to search.
        patterns: Glob patterns (e.g. ["*.env", "*secret*"]).

    Returns:
        List of matching files with metadata.
    """
    found_files: list[dict[str, Any]] = []

    for search_path in search_paths:
        if not search_path.exists():
            continue

        try:
            for pattern in patterns:
                for file_path in search_path.rglob(pattern):
                    if file_path.is_file():
                        if _should_ignore_file(file_path):
                            continue

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
            logger.debug("No access to %s: %s", search_path, e)

    return found_files


def scan_security(
    paths: PlatformPaths,
    check_ssh: bool = True,
    check_permissions: bool = True,
    sensitive_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """Run a full security scan.

    Args:
        paths: PlatformPaths instance for resolving paths.
        check_ssh: Whether to check SSH permissions.
        check_permissions: Whether to check file permissions.
        sensitive_patterns: Patterns for sensitive file discovery.

    Returns:
        Security scan results.
    """
    issues: list[SecurityIssue] = []
    sensitive_files: list[dict[str, Any]] = []

    if check_ssh:
        ssh_issues = check_ssh_permissions(paths)
        issues.extend(ssh_issues)

    if sensitive_patterns:
        search_paths = [paths.home, paths.home / "development", paths.home / "Documents"]
        sensitive_files = find_sensitive_files(search_paths, sensitive_patterns)

        if check_permissions:
            for file_info in sensitive_files:
                file_path = Path(file_info["path"])
                perm_issue = check_file_permissions(file_path)
                if perm_issue:
                    issues.append(perm_issue)

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
