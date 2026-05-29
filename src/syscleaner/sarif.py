"""SARIF 2.1.0 export for security findings."""

from __future__ import annotations

import json
from typing import Any

from syscleaner.models.entities import ScanBundle, SecurityIssue


def security_issues_to_sarif(issues: list[SecurityIssue], *, tool_version: str) -> dict[str, Any]:
    """Convert security issues to SARIF log dict."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for issue in issues:
        rule_id = f"syscleaner/{issue.category}".replace(" ", "_").lower()
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": issue.category,
                "shortDescription": {"text": issue.category},
                "defaultConfiguration": {"level": _severity_to_level(issue.severity)},
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _severity_to_level(issue.severity),
                "message": {"text": issue.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": issue.path},
                        },
                    },
                ],
            },
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "syscleaner",
                        "version": tool_version,
                        "informationUri": "https://github.com/FUYOH666/Cleaner-OS",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            },
        ],
    }


def _severity_to_level(severity: str) -> str:
    mapping = {"high": "error", "critical": "error", "medium": "warning", "low": "note"}
    return mapping.get(severity.lower(), "warning")


def export_sarif(bundle: ScanBundle) -> str:
    """Return SARIF JSON string for a scan bundle."""
    log = security_issues_to_sarif(bundle.security_issues, tool_version=bundle.tool_version)
    if not bundle.security_issues and bundle.security_results.get("issues"):
        from syscleaner.scan_bundle import security_dict_to_issues

        issues = security_dict_to_issues(bundle.security_results)
        log = security_issues_to_sarif(issues, tool_version=bundle.tool_version)
    return json.dumps(log, indent=2)
