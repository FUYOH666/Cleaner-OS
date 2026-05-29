"""Core data models for System Cleaner."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from syscleaner import __version__


class RiskTier(StrEnum):
    """Cleanup risk classification."""

    SAFE = "safe"
    MODERATE = "moderate"
    RISKY = "risky"


class ActionType(StrEnum):
    """How a cleanup action is executed."""

    NATIVE_CLI = "native_cli"
    DELETE_PATH = "delete_path"
    EMPTY_TRASH = "empty_trash"
    MANUAL = "manual"


class Finding(BaseModel):
    """A single reclaimable or notable item discovered during scan."""

    id: str
    recognizer_id: str
    category: str
    title: str
    path: str | None = None
    size_bytes: int = 0
    risk: RiskTier = RiskTier.MODERATE
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Action(BaseModel):
    """Executable cleanup step derived from findings."""

    id: str
    finding_id: str
    action_type: ActionType
    title: str
    risk: RiskTier
    command: list[str] = Field(default_factory=list)
    path: str | None = None
    requires_confirm: bool = True
    dry_run_supported: bool = True
    manual_reason: str | None = None


class SecurityIssue(BaseModel):
    """Security audit finding."""

    path: str
    category: str
    severity: str
    description: str
    recommendation: str | None = None


class CleanupPlan(BaseModel):
    """Plan generated from a scan bundle."""

    schema_version: str = "1.0"
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )
    actions: list[Action] = Field(default_factory=list)
    total_reclaimable_bytes: int = 0
    by_risk: dict[str, int] = Field(default_factory=dict)


class ScanBundle(BaseModel):
    """Unified scan output (--save-results format)."""

    schema_version: str = "1.0"
    tool_version: str = Field(default_factory=lambda: __version__)
    platform: str = ""
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )
    findings: list[Finding] = Field(default_factory=list)
    security_issues: list[SecurityIssue] = Field(default_factory=list)
    # Legacy sections preserved for report compatibility
    scan_results: dict[str, Any] = Field(default_factory=dict)
    security_results: dict[str, Any] = Field(default_factory=dict)
    cleanup_analysis: dict[str, Any] = Field(default_factory=dict)
    ml_cache_results: dict[str, Any] | None = None
    dependency_results: dict[str, Any] | None = None

    def model_dump_json_pretty(self) -> str:
        return self.model_dump_json(indent=2)
