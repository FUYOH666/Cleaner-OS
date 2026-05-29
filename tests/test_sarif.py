"""SARIF export tests."""

from syscleaner.models.entities import ScanBundle, SecurityIssue
from syscleaner.sarif import export_sarif, security_issues_to_sarif


def test_sarif_structure() -> None:
    issues = [
        SecurityIssue(
            path="/home/user/.env",
            category="sensitive_file",
            severity="high",
            description="World-readable .env",
            recommendation="chmod 600",
        ),
    ]
    log = security_issues_to_sarif(issues, tool_version="1.0.0")
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    assert len(log["runs"][0]["results"]) == 1
    assert log["runs"][0]["results"][0]["level"] == "error"


def test_export_sarif_from_bundle() -> None:
    bundle = ScanBundle(
        security_issues=[
            SecurityIssue(
                path="/tmp/key",
                category="ssh",
                severity="medium",
                description="Weak permissions",
            ),
        ],
    )
    content = export_sarif(bundle)
    assert "syscleaner" in content
    assert "ssh" in content
