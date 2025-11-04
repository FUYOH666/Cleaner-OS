"""Модули сканирования системы."""

from syscleaner.scanner.applications import scan_application_support
from syscleaner.scanner.caches import scan_caches
from syscleaner.scanner.hidden import scan_hidden_files
from syscleaner.scanner.logs import scan_logs
from syscleaner.scanner.projects import scan_project_artifacts
from syscleaner.scanner.trash import scan_trash

__all__ = [
    "scan_caches",
    "scan_application_support",
    "scan_hidden_files",
    "scan_project_artifacts",
    "scan_logs",
    "scan_trash",
]

