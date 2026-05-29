"""Golden fixture load and plan."""

from pathlib import Path

from syscleaner.plan_builder import build_plan_from_bundle
from syscleaner.scan_bundle import load_scan_bundle

FIXTURE = Path(__file__).parent / "fixtures" / "scan_sample.json"


def test_fixture_loads_and_builds_plan() -> None:
    import json

    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    bundle = load_scan_bundle(data)
    assert len(bundle.findings) == 2
    assert len(bundle.security_issues) == 1
    plan = build_plan_from_bundle(bundle)
    assert len(plan.actions) >= 1
