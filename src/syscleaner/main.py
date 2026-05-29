"""Main CLI module for System Cleaner."""

import json
import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from syscleaner import __version__
from syscleaner.analyzer import analyze_python_dependencies, scan_ml_cache, scan_security
from syscleaner.apply.orchestrator import apply_plan
from syscleaner.cleanup import analyze_cleanup_opportunities
from syscleaner.config import load_config
from syscleaner.models.entities import RiskTier, ScanBundle
from syscleaner.plan_builder import build_plan_from_bundle
from syscleaner.platform import PlatformPaths
from syscleaner.platform.detector import CURRENT_PLATFORM, IS_LINUX, IS_MACOS
from syscleaner.platform.linux import detect_linux_distro
from syscleaner.platform.system_info import detect_gpu, get_home_disk_info
from syscleaner.reporter import generate_json_report, generate_markdown_report, save_report
from syscleaner.sarif import export_sarif
from syscleaner.scan_bundle import build_scan_bundle, load_scan_bundle
from syscleaner.scanner import (
    scan_application_support,
    scan_caches,
    scan_hidden_files,
    scan_logs,
    scan_project_artifacts,
    scan_trash,
)

# Logging: time · level · service · message · metadata
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s [%(pathname)s:%(lineno)d]",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

app = typer.Typer(
    name="syscleaner",
    help="Universal CLI for system cleanup and audit (macOS and Linux)",
    add_completion=False,
)
console = Console()


def _load_bundle_file(path: str) -> ScanBundle:
    with open(path, encoding="utf-8") as f:
        return load_scan_bundle(json.load(f))


def print_findings_table(bundle: ScanBundle) -> None:
    """Print recognizer findings summary."""
    if not bundle.findings:
        return
    table = Table(title="Recognizer Findings (top 15)")
    table.add_column("Risk", style="yellow")
    table.add_column("Category", style="cyan")
    table.add_column("Title")
    table.add_column("Size", style="green")
    for finding in sorted(bundle.findings, key=lambda x: x.size_bytes, reverse=True)[:15]:
        size_mb = finding.size_bytes / (1024 * 1024)
        table.add_row(
            finding.risk.value,
            finding.category,
            finding.title[:50],
            f"{size_mb:.1f} MB",
        )
    console.print(table)
    console.print()


def print_summary_table(
    scan_results: dict,
    security_results: dict,
    cleanup_analysis: dict,
    ml_cache_results: dict | None = None,
    dependency_results: dict | None = None,
    bundle: ScanBundle | None = None,
) -> None:
    """Print summary table of scan results."""
    table = Table(title="Scan Summary")

    table.add_column("Category", style="cyan")
    table.add_column("Value", style="green")

    # Total size
    total_size_mb = (
        sum(item["size_mb"] for item in scan_results.get("caches", []))
        + sum(item["size_mb"] for item in scan_results.get("orphaned_apps", []))
        + sum(item["size_mb"] for item in scan_results.get("hidden_files", []))
    )
    table.add_row("Total data size", f"{total_size_mb:.2f} MB")

    # Caches
    caches_count = len(scan_results.get("caches", []))
    table.add_row("Caches found", str(caches_count))

    # Orphaned apps
    orphaned_count = len(scan_results.get("orphaned_apps", []))
    table.add_row("Possible app leftovers", str(orphaned_count))

    # Hidden files
    hidden_count = len(scan_results.get("hidden_files", []))
    table.add_row("Large hidden files", str(hidden_count))

    # Project artifacts
    artifacts_count = len(scan_results.get("project_artifacts", []))
    table.add_row("Project artifact types", str(artifacts_count))

    # ML caches
    if ml_cache_results:
        ml_total = ml_cache_results.get("total_models", 0)
        ml_size_gb = ml_cache_results.get("total_size_gb", 0)
        table.add_row("ML models in cache", f"{ml_total} ({ml_size_gb:.2f} GB)")
        unused_ml = ml_cache_results.get("unused_models_count", 0)
        if unused_ml > 0:
            unused_size_gb = ml_cache_results.get("unused_size_gb", 0)
            table.add_row(
                "Unused ML models",
                f"{unused_ml} ({unused_size_gb:.2f} GB)",
                style="yellow",
            )

    # Dependencies
    if dependency_results:
        dep_projects = dependency_results.get("total_projects", 0)
        dep_conflicts = len(dependency_results.get("conflicts", []))
        dep_unused = len(dependency_results.get("unused_dependencies", []))
        dep_outdated = len(dependency_results.get("outdated_dependencies", []))
        table.add_row("Projects checked", str(dep_projects))
        if dep_conflicts > 0:
            table.add_row("Dependency conflicts", str(dep_conflicts), style="red")
        if dep_unused > 0:
            table.add_row("Unused dependencies", str(dep_unused), style="yellow")
        if dep_outdated > 0:
            table.add_row("Outdated dependencies", str(dep_outdated), style="yellow")

    # Security
    security_issues = security_results.get("total_issues", 0)
    high_severity = security_results.get("high_severity_issues", 0)
    table.add_row("Security issues", str(security_issues))
    if high_severity > 0:
        table.add_row("Critical issues", str(high_severity), style="red")

    # Cleanup
    reclaimable_gb = cleanup_analysis.get("total_reclaimable_gb", 0)
    table.add_row("Potentially reclaimable", f"{reclaimable_gb:.2f} GB", style="green")

    if bundle and bundle.findings:
        findings_gb = sum(f.size_bytes for f in bundle.findings) / (1024**3)
        table.add_row("Recognizer findings", str(len(bundle.findings)))
        table.add_row("Recognizer reclaimable", f"{findings_gb:.2f} GB", style="green")

    console.print(table)


@app.command()
def scan(
    all: Annotated[bool, typer.Option("--all", help="Run full system scan")] = False,
    caches: Annotated[bool, typer.Option("--caches", help="Scan caches")] = False,
    security: Annotated[bool, typer.Option("--security", help="Check security")] = False,
    projects: Annotated[bool, typer.Option("--projects", help="Scan projects")] = False,
    dependencies: Annotated[
        bool, typer.Option("--dependencies", help="Analyze dependencies")
    ] = False,
    ml_cache: Annotated[bool, typer.Option("--ml-cache", help="Analyze ML caches")] = False,
    config_path: Annotated[str | None, typer.Option("--config", help="Path to config.yaml")] = None,
    save_results: Annotated[
        str | None,
        typer.Option("--save-results", help="Save results to JSON file"),
    ] = None,
) -> None:
    """
    Run system scan.

    Use --all for full scan or select individual categories.
    """
    try:
        settings = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Config load error: {e}[/red]")
        sys.exit(1)

    paths = PlatformPaths()
    project_dirs = paths.find_project_directories()
    if not project_dirs:
        fallback_dir = paths.home / "development"
        if fallback_dir.exists():
            project_dirs = [fallback_dir]

    scan_results: dict = {
        "caches": [],
        "orphaned_apps": [],
        "hidden_files": [],
        "project_artifacts": [],
        "logs": [],
        "trash": {},
    }
    security_results: dict = {}
    cleanup_analysis: dict = {}
    ml_cache_results: dict | None = None
    dependency_results: dict | None = None

    empty_dep_results = {
        "total_projects": 0,
        "conflicts": [],
        "unused_dependencies": [],
        "outdated_dependencies": [],
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        if all or caches:
            task = progress.add_task("Scanning caches...", total=None)
            scan_results["caches"] = scan_caches(paths, settings.scan.exclude_paths)
            progress.update(task, completed=True)

        if all or caches:
            task = progress.add_task("Finding app leftovers...", total=None)
            scan_results["orphaned_apps"] = scan_application_support(paths)
            progress.update(task, completed=True)

        if all:
            task = progress.add_task("Finding large hidden files...", total=None)
            scan_results["hidden_files"] = scan_hidden_files(paths, settings.scan.min_size_mb)
            progress.update(task, completed=True)

        if all or projects:
            task = progress.add_task("Scanning projects...", total=None)
            scan_results["project_artifacts"] = scan_project_artifacts(
                project_dirs,
                settings.cleanup.safe_to_delete_patterns,
            )
            progress.update(task, completed=True)

        if all or caches:
            task = progress.add_task("Scanning logs...", total=None)
            scan_results["logs"] = scan_logs(paths)
            progress.update(task, completed=True)

        if all or caches:
            task = progress.add_task("Checking trash...", total=None)
            scan_results["trash"] = scan_trash(paths)
            progress.update(task, completed=True)

        if all or security:
            task = progress.add_task("Checking security...", total=None)
            security_results = scan_security(
                paths,
                check_ssh=settings.security.check_ssh_permissions,
                check_permissions=settings.security.check_file_permissions,
                sensitive_patterns=settings.security.sensitive_patterns
                if settings.security.sensitive_patterns
                else None,
            )
            progress.update(task, completed=True)

        if all or ml_cache or settings.scan.check_ml_cache:
            task = progress.add_task("Analyzing ML caches...", total=None)
            try:
                ml_cache_results = scan_ml_cache(paths)
            except Exception as e:
                logger.error("ML cache analysis error: %s", e)
                ml_cache_results = {}
            progress.update(task, completed=True)

        if all or dependencies or settings.scan.check_dependencies:
            task = progress.add_task("Analyzing dependencies...", total=None)
            try:
                if project_dirs:
                    dependency_results = analyze_python_dependencies(project_dirs)
                else:
                    dependency_results = empty_dep_results
            except Exception as e:
                logger.error("Dependency analysis error: %s", e)
                dependency_results = empty_dep_results
            progress.update(task, completed=True)

        if all or caches or projects or ml_cache:
            task = progress.add_task("Analyzing cleanup opportunities...", total=None)
            cleanup_analysis = analyze_cleanup_opportunities(
                scan_results,
                ml_cache_results=ml_cache_results,
                safe_patterns=settings.cleanup.safe_to_delete_patterns,
            )
            progress.update(task, completed=True)

    bundle = build_scan_bundle(
        scan_results=scan_results,
        security_results=security_results,
        cleanup_analysis=cleanup_analysis,
        ml_cache_results=ml_cache_results,
        dependency_results=dependency_results,
        paths=paths,
        settings=settings,
    )

    console.print("\n")
    print_summary_table(
        scan_results,
        security_results,
        cleanup_analysis,
        ml_cache_results,
        dependency_results,
        bundle=bundle,
    )
    print_findings_table(bundle)

    if security_results.get("high_severity_issues", 0) > 0:
        console.print("\n[red]Critical security issues found![/red]")
        console.print("\n[bold]Top critical issues:[/bold]\n")

        high_severity_issues = [
            issue for issue in security_results.get("issues", []) if issue.get("severity") == "high"
        ][:10]

        for idx, issue in enumerate(high_severity_issues, 1):
            sev = issue.get("severity", "unknown").upper()
            cat = issue.get("category", "Unknown")
            console.print(f"[red]{idx}.[/red] [{sev}] {cat}")
            console.print(f"    Path: [dim]{issue.get('path', 'N/A')}[/dim]")
            console.print(f"    Description: {issue.get('description', 'N/A')}")

            category = issue.get("category", "").lower()
            if "ssh" in category:
                msg = "Wrong permissions may allow attackers to access servers"
            elif "permission" in category or "file" in category:
                msg = "Overly open permissions may leak confidential data"
            elif "sensitive" in category:
                msg = "Files with secrets may be compromised in a data leak"
            else:
                msg = "Requires immediate attention to prevent data leak or unauthorized access"
            console.print(f"    [yellow]Why critical:[/yellow] {msg}")

            if issue.get("recommendation"):
                console.print(f"    [green]Recommendation:[/green] {issue['recommendation']}")
            console.print()

        if security_results.get("high_severity_issues", 0) > 10:
            extra = security_results.get("high_severity_issues", 0) - 10
            console.print(f"[dim]... and {extra} more critical issues[/dim]\n")

        console.print("[yellow]For full report with all issues:[/yellow]")
        console.print(
            "  1. Save results: [bold]syscleaner scan --all --save-results results.json[/bold]"
        )
        console.print(
            "  2. Generate report: [bold]syscleaner report --format markdown "
            "--output report.md --from-scan results.json[/bold]"
        )
        console.print()

    if save_results:
        results_path = Path(save_results)
        results_path.parent.mkdir(parents=True, exist_ok=True)
        with results_path.open("w", encoding="utf-8") as f:
            f.write(bundle.model_dump_json(indent=2))
        console.print(f"[green]✓[/green] Results saved to {results_path}")
        console.print(
            "[dim]Next: syscleaner plan --from-scan "
            f"{results_path} | syscleaner apply --from-scan {results_path} --dry-run[/dim]",
        )


@app.command()
def report(
    format: Annotated[
        str, typer.Option("--format", "-f", help="Report format (markdown/json)")
    ] = "markdown",
    output: Annotated[
        str | None, typer.Option("--output", "-o", help="Output path for report")
    ] = None,
    scan_results_file: Annotated[
        str | None,
        typer.Option("--from-scan", help="Path to scan results JSON file"),
    ] = None,
) -> None:
    """
    Generate report from scan results.

    Use --from-scan to load previously saved results, or run scan with --save-results first.
    """
    if scan_results_file:
        try:
            bundle = _load_bundle_file(scan_results_file)
            scan_results = bundle.scan_results
            security_results = bundle.security_results
            cleanup_analysis = bundle.cleanup_analysis
            ml_cache_results = bundle.ml_cache_results
            dependency_results = bundle.dependency_results
        except Exception as e:
            console.print(f"[red]Error loading scan results: {e}[/red]")
            sys.exit(1)
    else:
        console.print("[yellow]Run scan first to generate report[/yellow]")
        console.print("Use: syscleaner scan --all --save-results")
        return

    platform_name = f"{CURRENT_PLATFORM.value}"
    if IS_MACOS:
        import platform as plat

        platform_name = f"macOS {plat.release()}"
    elif IS_LINUX:
        import platform as plat

        platform_name = f"Linux {plat.release()}"

    if format == "markdown":
        report_content = generate_markdown_report(
            scan_results,
            security_results,
            cleanup_analysis,
            ml_cache_results,
            dependency_results,
            platform_name,
        )
    elif format == "json":
        report_content = generate_json_report(
            scan_results,
            security_results,
            cleanup_analysis,
            ml_cache_results,
            dependency_results,
            platform_name,
        )
    else:
        console.print(f"[red]Unsupported format: {format}[/red]")
        sys.exit(1)

    if output:
        output_path = Path(output)
        save_report(report_content, output_path, format_type=format)
        console.print(f"[green]✓[/green] Report saved to {output_path}")
    else:
        console.print(report_content)


@app.command()
def plan(
    scan_results_file: Annotated[str, typer.Option("--from-scan", help="Scan JSON path")],
    target_gb: Annotated[
        float | None,
        typer.Option("--target-gb", help="Budget: stop adding actions after this size"),
    ] = None,
    tier: Annotated[
        str,
        typer.Option("--tier", help="Max risk tier: safe, moderate, risky"),
    ] = "moderate",
) -> None:
    """Build a human-readable cleanup plan from a saved scan."""
    try:
        bundle = _load_bundle_file(scan_results_file)
    except Exception as e:
        console.print(f"[red]Error loading scan: {e}[/red]")
        sys.exit(1)

    max_risk = RiskTier(tier)
    target_bytes = int(target_gb * 1024**3) if target_gb else None
    cleanup_plan = build_plan_from_bundle(
        bundle,
        max_risk=max_risk,
        target_bytes=target_bytes,
    )

    table = Table(title="Cleanup Plan")
    table.add_column("Risk")
    table.add_column("Type")
    table.add_column("Action")
    table.add_column("Detail")
    for action in cleanup_plan.actions[:30]:
        if action.command:
            detail = " ".join(action.command)
        else:
            detail = action.path or action.manual_reason or ""
        table.add_row(
            action.risk.value,
            action.action_type.value,
            action.title[:40],
            str(detail)[:60],
        )
    console.print(table)
    if len(cleanup_plan.actions) > 30:
        console.print(f"[dim]... and {len(cleanup_plan.actions) - 30} more actions[/dim]")
    gb = cleanup_plan.total_reclaimable_bytes / (1024**3)
    console.print(f"\n[bold]Actions:[/bold] {len(cleanup_plan.actions)}")
    console.print(f"[bold]Estimated reclaimable:[/bold] {gb:.2f} GB")
    console.print(f"[bold]By risk:[/bold] {cleanup_plan.by_risk}")


@app.command()
def apply(
    scan_results_file: Annotated[str, typer.Option("--from-scan", help="Scan JSON path")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only (default)")] = True,
    tier: Annotated[str, typer.Option("--tier", help="Max risk: safe, moderate, risky")] = "safe",
    allow_risky: Annotated[bool, typer.Option("--allow-risky", help="Allow risky tier")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmations")] = False,
    execute: Annotated[
        bool,
        typer.Option("--execute", help="Actually run (disables dry-run)"),
    ] = False,
) -> None:
    """Apply cleanup plan from a saved scan. Default is dry-run."""
    try:
        bundle = _load_bundle_file(scan_results_file)
    except Exception as e:
        console.print(f"[red]Error loading scan: {e}[/red]")
        sys.exit(1)

    max_risk = RiskTier(tier)
    plan_risk = RiskTier.RISKY if allow_risky else max_risk
    cleanup_plan = build_plan_from_bundle(bundle, max_risk=plan_risk)
    is_dry = dry_run and not execute

    if not is_dry:
        console.print("[yellow]Executing cleanup actions.[/yellow]")
    else:
        console.print("[cyan]Dry-run mode — no changes will be made.[/cyan]")

    result = apply_plan(
        cleanup_plan,
        dry_run=is_dry,
        max_risk=max_risk,
        allow_risky=allow_risky,
        yes=yes,
    )
    for msg in result.messages:
        console.print(msg)
    console.print(
        f"\n[bold]Summary:[/bold] executed={result.executed} "
        f"skipped={result.skipped} failed={result.failed} dry_run={result.dry_run}",
    )
    if result.failed:
        sys.exit(1)


@app.command(name="export-sarif")
def export_sarif_cmd(
    scan_results_file: Annotated[str, typer.Option("--from-scan", help="Scan JSON path")],
    output: Annotated[str, typer.Option("--output", "-o", help="SARIF output path")],
) -> None:
    """Export security findings as SARIF 2.1.0 for CI and GitHub Code Scanning."""
    try:
        bundle = _load_bundle_file(scan_results_file)
    except Exception as e:
        console.print(f"[red]Error loading scan: {e}[/red]")
        sys.exit(1)

    sarif_content = export_sarif(bundle)
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(sarif_content, encoding="utf-8")
    n = len(bundle.security_issues) or len(bundle.security_results.get("issues", []))
    console.print(f"[green]✓[/green] SARIF written to {out_path} ({n} issues)")


@app.command(name="export-schema")
def export_schema(
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Write JSON Schema to file"),
    ] = None,
) -> None:
    """Export ScanBundle JSON Schema for CI and integrations."""
    schema = ScanBundle.model_json_schema()
    text = json.dumps(schema, indent=2)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]✓[/green] Schema written to {output}")
    else:
        console.print(text)


@app.command()
def health() -> None:
    """Check system status and tool availability."""
    _health_impl()


@app.command(name="healthz")
def healthz() -> None:
    """Alias for health (readiness-style check for automation)."""
    _health_impl()


def _health_impl() -> None:
    """Internal health check implementation."""
    console.print("[bold]System Status Check[/bold]\n")

    python_version = sys.version_info
    py_ver = f"{python_version.major}.{python_version.minor}.{python_version.micro}"
    if python_version.major == 3 and python_version.minor >= 12:
        console.print(f"[green]✓[/green] Python {py_ver}")
    else:
        console.print(f"[red]✗[/red] Python {py_ver} (3.12+ required)")

    if IS_MACOS:
        import platform as plat

        console.print(f"[green]✓[/green] macOS {plat.release()}")
    elif IS_LINUX:
        distro = detect_linux_distro()
        if distro:
            distro_info = f"{distro.name}"
            if distro.version:
                distro_info += f" {distro.version}"
            console.print(f"[green]✓[/green] Linux ({distro_info})")
        else:
            import platform as plat

            console.print(f"[green]✓[/green] Linux {plat.release()}")
    else:
        import platform as plat

        console.print(f"[yellow]⚠[/yellow] Unsupported platform: {plat.system()}")

    console.print("\n[bold]System info:[/bold]")

    gpu_info = detect_gpu()
    if gpu_info.has_gpu:
        gpu_str = f"GPU: {gpu_info.gpu_type}"
        if gpu_info.gpu_model:
            gpu_str += f" ({gpu_info.gpu_model})"
        console.print(f"[green]✓[/green] {gpu_str}")
    else:
        console.print("[dim]GPU: not detected[/dim]")

    disk_info = get_home_disk_info()
    if disk_info:
        console.print(
            f"[green]✓[/green] Disk: {disk_info.total_gb:.1f} GB "
            f"(used: {disk_info.used_gb:.1f} GB, "
            f"free: {disk_info.free_gb:.1f} GB, "
            f"{disk_info.usage_percent:.1f}% used)"
        )

    paths = PlatformPaths()
    critical_paths = {
        "Home directory": paths.home,
        "Caches": paths.cache_dir(),
        "Application Support": paths.app_support_dir(),
        "Logs": paths.logs_dir(),
        ".ssh": paths.ssh_dir(),
    }

    console.print("\n[bold]Path availability:[/bold]")
    for name, path in critical_paths.items():
        if path.exists():
            console.print(f"[green]✓[/green] {name}: {path}")
        else:
            console.print(f"[yellow]⚠[/yellow] {name}: {path} (not found)")

    project_dirs = paths.find_project_directories()
    if project_dirs:
        console.print(f"\n[bold]Project directories ({len(project_dirs)}):[/bold]")
        for project_dir in project_dirs[:10]:
            console.print(f"[green]✓[/green] {project_dir}")
        if len(project_dirs) > 10:
            console.print(f"[dim]... and {len(project_dirs) - 10} more[/dim]")
    else:
        console.print("\n[yellow]⚠[/yellow] No project directories found")
        console.print("[dim]Tool will search standard locations during scan[/dim]")

    console.print("\n[bold]Configuration:[/bold]")
    try:
        settings = load_config()
        console.print("[green]✓[/green] Config loaded successfully")
        console.print(f"  - Min size for report: {settings.scan.min_size_mb} MB")
        console.print(f"  - Security check: {settings.scan.check_security}")
        console.print(f"  - Project artifacts check: {settings.scan.check_project_artifacts}")
        console.print(f"  - Dependencies check: {settings.scan.check_dependencies}")
        console.print(f"  - ML cache check: {settings.scan.check_ml_cache}")
    except Exception as e:
        console.print(f"[red]✗[/red] Config load error: {e}")

    console.print(f"\n[bold]System Cleaner v{__version__}[/bold]")


def main() -> None:
    """Application entry point."""
    app()


if __name__ == "__main__":
    main()
