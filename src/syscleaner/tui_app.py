"""Textual TUI for reviewing and applying cleanup plans."""

from __future__ import annotations

import json
from pathlib import Path

from syscleaner.apply.orchestrator import ApplyResult, apply_plan
from syscleaner.i18n import t
from syscleaner.models.entities import CleanupPlan, RiskTier
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


def execute_safe_plan(plan: CleanupPlan) -> ApplyResult:
    """Run safe-tier apply with confirmation flags (used by TUI and tests)."""
    return apply_plan(
        plan,
        dry_run=False,
        max_risk=RiskTier.SAFE,
        allow_risky=False,
        yes=True,
    )


class CleanupTuiApp(App):
    """Interactive plan review (dry-run apply by default)."""

    CSS = """
    Screen { padding: 1; }
    DataTable { height: 1fr; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("a", "apply_dry", "Dry-run apply"),
        ("e", "arm_execute", "Arm execute"),
    ]

    def __init__(self, scan_path: Path, tier: RiskTier = RiskTier.MODERATE) -> None:
        super().__init__()
        self.scan_path = scan_path
        self.tier = tier
        self._execute_armed = False
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
        yield Vertical(
            table,
            Button("Dry-run apply (a)", id="apply"),
            Button("Execute safe tier — confirm twice (e)", id="execute"),
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply":
            self.action_apply_dry()
        elif event.button.id == "execute":
            self.action_execute_safe()

    def action_apply_dry(self) -> None:
        result = apply_plan(self.plan, dry_run=True, max_risk=self.tier)
        self.notify(
            f"Dry-run: executed={result.executed} skipped={result.skipped}",
            timeout=5,
        )

    def action_arm_execute(self) -> None:
        self.action_execute_safe()

    def action_execute_safe(self) -> None:
        if not self._execute_armed:
            self._execute_armed = True
            self.notify(t("tui_confirm_execute"), timeout=6)
            return
        self._execute_armed = False
        result = execute_safe_plan(self.plan)
        self.notify(
            t(
                "tui_execute_done",
                executed=result.executed,
                skipped=result.skipped,
                failed=result.failed,
            ),
            timeout=8,
        )


def run_tui(scan_path: str, tier: str = "moderate") -> None:
    """Launch TUI for a scan file."""
    app = CleanupTuiApp(Path(scan_path).expanduser(), tier=RiskTier(tier))
    app.run()
