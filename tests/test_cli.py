"""CLI integration tests via Typer CliRunner."""

import json
from pathlib import Path

from typer.testing import CliRunner

from syscleaner.main import app

runner = CliRunner()
FIXTURE = Path(__file__).parent / "fixtures" / "scan_sample.json"


def test_health_exits_zero() -> None:
    result = runner.invoke(app, ["health"])
    assert result.exit_code == 0


def test_health_ru_locale() -> None:
    result = runner.invoke(app, ["--lang", "ru", "health"])
    assert result.exit_code == 0
    assert "Проверка" in result.stdout or "Python" in result.stdout


def test_export_sarif_from_fixture(tmp_path: Path) -> None:
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    out = tmp_path / "out.sarif"
    result = runner.invoke(
        app,
        ["export-sarif", "--from-scan", str(scan_path), "-o", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


def test_plan_from_fixture() -> None:
    result = runner.invoke(app, ["plan", "--from-scan", str(FIXTURE)])
    assert result.exit_code == 0
    assert "Cleanup" in result.stdout or "очистки" in result.stdout or "Plan" in result.stdout


def test_export_schema() -> None:
    result = runner.invoke(app, ["export-schema"])
    assert result.exit_code == 0
    assert "schema_version" in result.stdout
