"""Главный модуль CLI приложения System Cleaner."""

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
from syscleaner.cleanup import analyze_cleanup_opportunities
from syscleaner.config import load_config
from syscleaner.platform import PlatformPaths
from syscleaner.platform.detector import IS_LINUX, IS_MACOS, CURRENT_PLATFORM
from syscleaner.platform.linux import detect_linux_distro
from syscleaner.platform.system_info import detect_gpu, get_home_disk_info
from syscleaner.reporter import generate_json_report, generate_markdown_report, save_report
from syscleaner.scanner import (
    scan_application_support,
    scan_caches,
    scan_hidden_files,
    scan_logs,
    scan_project_artifacts,
    scan_trash,
)

# Настройка логирования
# Формат: ts level service msg meta (с pathname:lineno для отладки)
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s [%(pathname)s:%(lineno)d]",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

app = typer.Typer(
    name="syscleaner",
    help="Универсальный инструмент для очистки и аудита системы (macOS и Linux)",
    add_completion=False,
)
console = Console()


def print_summary_table(
    scan_results: dict,
    security_results: dict,
    cleanup_analysis: dict,
    ml_cache_results: dict | None = None,
    dependency_results: dict | None = None,
) -> None:
    """Вывести сводную таблицу результатов."""
    table = Table(title="Сводка сканирования")

    table.add_column("Категория", style="cyan")
    table.add_column("Значение", style="green")

    # Общий размер
    total_size_mb = (
        sum(item["size_mb"] for item in scan_results.get("caches", []))
        + sum(item["size_mb"] for item in scan_results.get("orphaned_apps", []))
        + sum(item["size_mb"] for item in scan_results.get("hidden_files", []))
    )
    table.add_row("Общий размер данных", f"{total_size_mb:.2f} MB")

    # Кэши
    caches_count = len(scan_results.get("caches", []))
    table.add_row("Найдено кэшей", str(caches_count))

    # Остатки приложений
    orphaned_count = len(scan_results.get("orphaned_apps", []))
    table.add_row("Возможных остатков приложений", str(orphaned_count))

    # Скрытые файлы
    hidden_count = len(scan_results.get("hidden_files", []))
    table.add_row("Больших скрытых файлов", str(hidden_count))

    # Артефакты проектов
    artifacts_count = len(scan_results.get("project_artifacts", []))
    table.add_row("Типов артефактов проектов", str(artifacts_count))

    # ML кэши
    if ml_cache_results:
        ml_total = ml_cache_results.get("total_models", 0)
        ml_size_gb = ml_cache_results.get("total_size_gb", 0)
        table.add_row("ML моделей в кэше", f"{ml_total} ({ml_size_gb:.2f} GB)")
        unused_ml = ml_cache_results.get("unused_models_count", 0)
        if unused_ml > 0:
            unused_size_gb = ml_cache_results.get("unused_size_gb", 0)
            table.add_row(
                "Неиспользуемых ML моделей",
                f"{unused_ml} ({unused_size_gb:.2f} GB)",
                style="yellow",
            )

    # Зависимости
    if dependency_results:
        dep_projects = dependency_results.get("total_projects", 0)
        dep_conflicts = len(dependency_results.get("conflicts", []))
        dep_unused = len(dependency_results.get("unused_dependencies", []))
        dep_outdated = len(dependency_results.get("outdated_dependencies", []))
        table.add_row("Проектов проверено", str(dep_projects))
        if dep_conflicts > 0:
            table.add_row("Конфликтов зависимостей", str(dep_conflicts), style="red")
        if dep_unused > 0:
            table.add_row("Неиспользуемых зависимостей", str(dep_unused), style="yellow")
        if dep_outdated > 0:
            table.add_row("Устаревших зависимостей", str(dep_outdated), style="yellow")

    # Безопасность
    security_issues = security_results.get("total_issues", 0)
    high_severity = security_results.get("high_severity_issues", 0)
    table.add_row("Проблем безопасности", str(security_issues))
    if high_severity > 0:
        table.add_row("Критичных проблем", str(high_severity), style="red")

    # Очистка
    reclaimable_gb = cleanup_analysis.get("total_reclaimable_gb", 0)
    table.add_row("Потенциально можно освободить", f"{reclaimable_gb:.2f} GB", style="green")

    console.print(table)


@app.command()
def scan(
    all: Annotated[bool, typer.Option("--all", help="Выполнить полное сканирование")] = False,
    caches: Annotated[bool, typer.Option("--caches", help="Сканировать кэши")] = False,
    security: Annotated[bool, typer.Option("--security", help="Проверить безопасность")] = False,
    projects: Annotated[bool, typer.Option("--projects", help="Сканировать проекты")] = False,
    dependencies: Annotated[
        bool, typer.Option("--dependencies", help="Анализировать зависимости")
    ] = False,
    ml_cache: Annotated[
        bool, typer.Option("--ml-cache", help="Анализировать ML кэши")
    ] = False,
    config_path: Annotated[str | None, typer.Option("--config", help="Путь к config.yaml")] = None,
    save_results: Annotated[
        str | None,
        typer.Option("--save-results", help="Сохранить результаты в JSON файл"),
    ] = None,
) -> None:
    """
    Выполнить сканирование системы.

    Используйте --all для полного сканирования или выберите отдельные категории.
    """
    try:
        settings = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Ошибка загрузки конфигурации: {e}[/red]")
        sys.exit(1)

    paths = PlatformPaths()
    # Автоматически находим директории проектов
    project_dirs = paths.find_project_directories()
    # Если не найдено, используем стандартную директорию как fallback
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

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Сканирование кэшей
        if all or caches:
            task = progress.add_task("Сканирование кэшей...", total=None)
            scan_results["caches"] = scan_caches(paths, settings.scan.exclude_paths)
            progress.update(task, completed=True)

        # Сканирование остатков приложений
        if all or caches:
            task = progress.add_task("Поиск остатков приложений...", total=None)
            scan_results["orphaned_apps"] = scan_application_support(paths)
            progress.update(task, completed=True)

        # Сканирование скрытых файлов
        if all:
            task = progress.add_task("Поиск больших скрытых файлов...", total=None)
            scan_results["hidden_files"] = scan_hidden_files(paths, settings.scan.min_size_mb)
            progress.update(task, completed=True)

        # Сканирование артефактов проектов
        if all or projects:
            task = progress.add_task("Сканирование проектов...", total=None)
            scan_results["project_artifacts"] = scan_project_artifacts(
                project_dirs,
                settings.cleanup.safe_to_delete_patterns,
            )
            progress.update(task, completed=True)

        # Сканирование логов
        if all or caches:
            task = progress.add_task("Сканирование логов...", total=None)
            scan_results["logs"] = scan_logs(paths)
            progress.update(task, completed=True)

        # Сканирование корзины
        if all or caches:
            task = progress.add_task("Проверка корзины...", total=None)
            scan_results["trash"] = scan_trash(paths)
            progress.update(task, completed=True)

        # Проверка безопасности
        if all or security:
            task = progress.add_task("Проверка безопасности...", total=None)
            security_results = scan_security(
                paths,
                check_ssh=settings.security.check_ssh_permissions,
                check_permissions=settings.security.check_file_permissions,
                sensitive_patterns=settings.security.sensitive_patterns
                if settings.security.sensitive_patterns
                else None,
            )
            progress.update(task, completed=True)

        # Анализ ML кэшей
        if all or ml_cache or settings.scan.check_ml_cache:
            task = progress.add_task("Анализ ML кэшей...", total=None)
            try:
                ml_cache_results = scan_ml_cache(paths)
            except Exception as e:
                logger.error(f"Ошибка при анализе ML кэшей: {e}")
                ml_cache_results = {}
            progress.update(task, completed=True)

        # Анализ зависимостей
        if all or dependencies or settings.scan.check_dependencies:
            task = progress.add_task("Анализ зависимостей...", total=None)
            try:
                if project_dirs:
                    dependency_results = analyze_python_dependencies(project_dirs)
                else:
                    dependency_results = {"total_projects": 0, "conflicts": [], "unused_dependencies": [], "outdated_dependencies": []}
            except Exception as e:
                logger.error(f"Ошибка при анализе зависимостей: {e}")
                dependency_results = {}
            progress.update(task, completed=True)

        # Анализ возможностей очистки
        if all or caches or projects or ml_cache:
            task = progress.add_task("Анализ возможностей очистки...", total=None)
            cleanup_analysis = analyze_cleanup_opportunities(
                scan_results,
                ml_cache_results=ml_cache_results,
                safe_patterns=settings.cleanup.safe_to_delete_patterns,
            )
            progress.update(task, completed=True)

    # Выводим результаты
    console.print("\n")
    print_summary_table(
        scan_results,
        security_results,
        cleanup_analysis,
        ml_cache_results,
        dependency_results,
    )

    # Предупреждения о безопасности
    if security_results.get("high_severity_issues", 0) > 0:
        console.print("\n[red]⚠️  Найдены критические проблемы безопасности![/red]")
        console.print("\n[bold]Топ критических проблем:[/bold]\n")
        
        # Выводим топ-10 критических проблем
        high_severity_issues = [
            issue for issue in security_results.get("issues", [])
            if issue.get("severity") == "high"
        ][:10]
        
        for idx, issue in enumerate(high_severity_issues, 1):
            console.print(f"[red]{idx}.[/red] [{issue.get('severity', 'unknown').upper()}] {issue.get('category', 'Unknown')}")
            console.print(f"    Путь: [dim]{issue.get('path', 'N/A')}[/dim]")
            console.print(f"    Описание: {issue.get('description', 'N/A')}")
            
            # Объяснение критичности
            category = issue.get('category', '').lower()
            if 'ssh' in category:
                console.print(f"    [yellow]⚠️  Почему критично:[/yellow] Неправильные права могут позволить злоумышленникам получить доступ к серверам и учетным записям")
            elif 'permission' in category or 'file' in category:
                console.print(f"    [yellow]⚠️  Почему критично:[/yellow] Слишком открытые права могут привести к утечке конфиденциальных данных")
            elif 'sensitive' in category:
                console.print(f"    [yellow]⚠️  Почему критично:[/yellow] Файлы с секретами могут быть скомпрометированы при утечке данных")
            else:
                console.print(f"    [yellow]⚠️  Почему критично:[/yellow] Требует немедленного внимания для предотвращения утечки данных или несанкционированного доступа")
            
            if issue.get("recommendation"):
                console.print(f"    [green]💡 Рекомендация:[/green] {issue['recommendation']}")
            console.print()
        
        if security_results.get("high_severity_issues", 0) > 10:
            console.print(f"[dim]... и еще {security_results.get('high_severity_issues', 0) - 10} критических проблем[/dim]\n")
        
        console.print("[yellow]💡 Для получения полного отчета со всеми проблемами:[/yellow]")
        console.print("   1. Сохраните результаты: [bold]syscleaner scan --all --save-results results.json[/bold]")
        console.print("   2. Создайте отчет: [bold]syscleaner report --format markdown --output report.md --from-scan results.json[/bold]")
        console.print()

    # Сохраняем результаты если нужно
    if save_results:
        import json

        results_data = {
            "scan_results": scan_results,
            "security_results": security_results,
            "cleanup_analysis": cleanup_analysis,
        }
        if ml_cache_results:
            results_data["ml_cache_results"] = ml_cache_results
        if dependency_results:
            results_data["dependency_results"] = dependency_results

        results_path = Path(save_results)
        results_path.parent.mkdir(parents=True, exist_ok=True)
        with results_path.open("w", encoding="utf-8") as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]✓[/green] Результаты сохранены в {results_path}")


@app.command()
def report(
    format: Annotated[
        str, typer.Option("--format", "-f", help="Формат отчета (markdown/json)")
    ] = "markdown",
    output: Annotated[
        str | None, typer.Option("--output", "-o", help="Путь для сохранения отчета")
    ] = None,
    scan_results_file: Annotated[
        str | None,
        typer.Option("--from-scan", help="Путь к файлу с результатами сканирования (JSON)"),
    ] = None,
) -> None:
    """
    Сгенерировать отчет по результатам сканирования.

    Используйте --from-scan для загрузки ранее сохраненных результатов или
    сначала выполните команду scan с опцией --save-results.
    """
    import json

    if scan_results_file:
        try:
            with open(scan_results_file, encoding="utf-8") as f:
                data = json.load(f)
            scan_results = data.get("scan_results", {})
            security_results = data.get("security_results", {})
            cleanup_analysis = data.get("cleanup_analysis", {})
            ml_cache_results = data.get("ml_cache_results")
            dependency_results = data.get("dependency_results")
        except Exception as e:
            console.print(f"[red]Ошибка загрузки результатов сканирования: {e}[/red]")
            sys.exit(1)
    else:
        console.print("[yellow]⚠️  Для генерации отчета сначала выполните команду scan[/yellow]")
        console.print("Используйте: syscleaner scan --all --save-results")
        return

    platform_name = f"{CURRENT_PLATFORM.value}"
    if IS_MACOS:
        import platform
        platform_name = f"macOS {platform.release()}"
    elif IS_LINUX:
        import platform
        platform_name = f"Linux {platform.release()}"

    # Генерируем отчет
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
        console.print(f"[red]Неподдерживаемый формат: {format}[/red]")
        sys.exit(1)

    # Сохраняем отчет
    if output:
        output_path = Path(output)
        save_report(report_content, output_path, format_type=format)
        console.print(f"[green]✓[/green] Отчет сохранен в {output_path}")
    else:
        # Выводим в консоль
        console.print(report_content)


@app.command()
def health() -> None:
    """Проверить состояние системы и доступность инструментов."""
    console.print("[bold]Проверка состояния системы[/bold]\n")

    # Проверка Python версии
    import sys

    python_version = sys.version_info
    if python_version.major == 3 and python_version.minor >= 12:
        console.print(
            f"[green]✓[/green] Python {python_version.major}.{python_version.minor}.{python_version.micro}"
        )
    else:
        console.print(
            f"[red]✗[/red] Python {python_version.major}.{python_version.minor}.{python_version.micro} (требуется 3.12+)",
        )

    # Проверка платформы
    import platform

    platform_name = platform.system()
    if IS_MACOS:
        console.print(f"[green]✓[/green] macOS {platform.release()}")
    elif IS_LINUX:
        distro = detect_linux_distro()
        if distro:
            distro_info = f"{distro.name}"
            if distro.version:
                distro_info += f" {distro.version}"
            console.print(f"[green]✓[/green] Linux {platform.release()} ({distro_info})")
        else:
            console.print(f"[green]✓[/green] Linux {platform.release()}")
    else:
        console.print(f"[yellow]⚠[/yellow] Неподдерживаемая платформа: {platform_name}")

    # Проверка железа
    console.print("\n[bold]Информация о системе:[/bold]")
    
    # GPU
    gpu_info = detect_gpu()
    if gpu_info.has_gpu:
        gpu_str = f"GPU: {gpu_info.gpu_type}"
        if gpu_info.gpu_model:
            gpu_str += f" ({gpu_info.gpu_model})"
        console.print(f"[green]✓[/green] {gpu_str}")
    else:
        console.print("[dim]GPU: не обнаружен[/dim]")
    
    # Диск
    disk_info = get_home_disk_info()
    if disk_info:
        console.print(
            f"[green]✓[/green] Диск: {disk_info.total_gb:.1f} GB "
            f"(использовано: {disk_info.used_gb:.1f} GB, "
            f"свободно: {disk_info.free_gb:.1f} GB, "
            f"занято: {disk_info.usage_percent:.1f}%)"
        )

    # Проверка доступности критичных путей
    paths = PlatformPaths()
    critical_paths = {
        "Домашняя директория": paths.home,
        "Кэши": paths.cache_dir(),
        "Поддержка приложений": paths.app_support_dir(),
        "Логи": paths.logs_dir(),
        ".ssh": paths.ssh_dir(),
    }

    console.print("\n[bold]Проверка доступности путей:[/bold]")
    for name, path in critical_paths.items():
        if path.exists():
            console.print(f"[green]✓[/green] {name}: {path}")
        else:
            console.print(f"[yellow]⚠[/yellow] {name}: {path} (не найдено)")

    # Найденные проекты
    project_dirs = paths.find_project_directories()
    if project_dirs:
        console.print(f"\n[bold]Найденные директории проектов ({len(project_dirs)}):[/bold]")
        for project_dir in project_dirs[:10]:  # Показываем первые 10
            console.print(f"[green]✓[/green] {project_dir}")
        if len(project_dirs) > 10:
            console.print(f"[dim]... и еще {len(project_dirs) - 10} директорий[/dim]")
    else:
        console.print("\n[yellow]⚠[/yellow] Директории проектов не найдены")
        console.print("[dim]Инструмент будет искать проекты в стандартных местах при сканировании[/dim]")

    # Проверка конфигурации
    console.print("\n[bold]Проверка конфигурации:[/bold]")
    try:
        settings = load_config()
        console.print("[green]✓[/green] Конфигурация загружена успешно")
        console.print(f"  - Минимальный размер для отчета: {settings.scan.min_size_mb} MB")
        console.print(f"  - Проверка безопасности: {settings.scan.check_security}")
        console.print(f"  - Проверка артефактов проектов: {settings.scan.check_project_artifacts}")
        console.print(f"  - Проверка зависимостей: {settings.scan.check_dependencies}")
        console.print(f"  - Проверка ML кэшей: {settings.scan.check_ml_cache}")
    except Exception as e:
        console.print(f"[red]✗[/red] Ошибка загрузки конфигурации: {e}")

    console.print(f"\n[bold]System Cleaner v{__version__}[/bold]")


def main() -> None:
    """Точка входа в приложение."""
    app()


if __name__ == "__main__":
    main()

