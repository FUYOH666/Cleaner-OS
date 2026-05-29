"""Textual TUI for reviewing and applying cleanup plans."""

from __future__ import annotations

import json
from pathlib import Path

from syscleaner.apply.orchestrator import apply_plan
from syscleaner.models.entities import RiskTier
from syscleaner.plan_builder import build_plan_from_bundle
from syscleaner.scan_bundle import load_scan_bundle

try:
    from textual.app import App, ComposeResult
    from textual.containers import Vertical
    from textual.widgets import Button, DataTable, Footer, Header, Static
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "TUI extra not installed. Run: uv sync --extra tui",
    ) from exc


class CleanupTuiApp(App):
    """Interactive plan review (dry-run apply by default)."""

    CSS = """
    Screen { padding: 1; }
    DataTable { height: 1fr; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("a", "apply_dry", "Dry-run apply"),
    ]

    def __init__(self, scan_path: Path, tier: RiskTier = RiskTier.MODERATE) -> None:
        super().__init__()
        self.scan_path = scan_path
        self.tier = tier
        with scan_path.open(encoding="utf-8") as f:
            self.bundle = load_scan_bundle(json.load(f))
        self.plan = build_plan_from_bundle(self.bundle, max_risk=tier)

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(f"Scan: {self.scan_path} | Actions: {len(self.plan.actions)}")
        table = DataTable()
        table.add_columns("Risk", "Type", "Title", "Detail")
        for action in self.plan.actions[:50]:
            detail = (
                " ".join(action.command)
                if action.command
                else (action.path or action.manual_reason or "")
            )
            table.add_row(
                action.risk.value,
                action.action_type.value,
                action.title[:40],
                str(detail)[:60],
            )
        yield Vertical(table, Button("Dry-run apply (a)", id="apply"))
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply":
            self.action_apply_dry()

    def action_apply_dry(self) -> None:
        result = apply_plan(self.plan, dry_run=True, max_risk=self.tier)
        self.notify(
            f"Dry-run: executed={result.executed} skipped={result.skipped}",
            timeout=5,
        )


def run_tui(scan_path: str, tier: str = "moderate") -> None:
    """Launch TUI for a scan file."""
    app = CleanupTuiApp(Path(scan_path).expanduser(), tier=RiskTier(tier))
    app.run()
