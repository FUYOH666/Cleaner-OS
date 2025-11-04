"""Модуль генерации отчетов (кроссплатформенный)."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_markdown_report(
    scan_results: dict[str, Any],
    security_results: dict[str, Any],
    cleanup_analysis: dict[str, Any],
    ml_cache_results: dict[str, Any] | None = None,
    dependency_results: dict[str, Any] | None = None,
    platform: str = "Unknown",
) -> str:
    """
    Сгенерировать Markdown отчет.

    Args:
        scan_results: Результаты сканирования.
        security_results: Результаты проверки безопасности.
        cleanup_analysis: Анализ возможностей очистки.
        ml_cache_results: Результаты анализа ML кэшей.
        dependency_results: Результаты анализа зависимостей.
        platform: Платформа системы.

    Returns:
        Markdown отчет в виде строки.
    """
    report_lines: list[str] = []

    report_lines.append("# System Cleaner Audit Report\n")
    report_lines.append(f"**Платформа:** {platform}\n")
    report_lines.append(f"**Дата сканирования:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Общая информация
    report_lines.append("## Общая информация\n")
    total_size_mb = (
        sum(item["size_mb"] for item in scan_results.get("caches", []))
        + sum(item["size_mb"] for item in scan_results.get("orphaned_apps", []))
        + sum(item["size_mb"] for item in scan_results.get("hidden_files", []))
    )
    report_lines.append(
        f"- **Общий размер найденных данных:** {total_size_mb:.2f} MB ({total_size_mb / 1024:.2f} GB)\n"
    )

    # ML кэши
    if ml_cache_results:
        report_lines.append("## ML Кэши моделей\n")
        report_lines.append(
            f"- **Всего моделей:** {ml_cache_results.get('total_models', 0)}\n"
        )
        report_lines.append(
            f"- **Общий размер:** {ml_cache_results.get('total_size_gb', 0):.2f} GB\n"
        )
        report_lines.append(
            f"- **Неиспользуемых моделей:** {ml_cache_results.get('unused_models_count', 0)}\n"
        )
        report_lines.append(
            f"- **Размер неиспользуемых:** {ml_cache_results.get('unused_size_gb', 0):.2f} GB\n"
        )
        report_lines.append("\n")

        # Детали по типам кэшей
        if ml_cache_results.get("models_by_type"):
            report_lines.append("### По типам кэшей\n")
            report_lines.append("| Тип | Количество | Размер |\n")
            report_lines.append("|-----|------------|--------|\n")
            for cache_type, models in ml_cache_results["models_by_type"].items():
                total_size = sum(m["size_gb"] for m in models)
                report_lines.append(
                    f"| {cache_type} | {len(models)} | {total_size:.2f} GB |\n"
                )
            report_lines.append("\n")

        # Топ моделей по размеру
        if ml_cache_results.get("models"):
            report_lines.append("### Топ моделей по размеру\n")
            report_lines.append("| Модель | Размер | Тип |\n")
            report_lines.append("|--------|--------|-----|\n")
            for model in ml_cache_results["models"][:10]:
                report_lines.append(
                    f"| {model['name']} | {model['size_gb']:.2f} GB | {model['cache_type']} |\n"
                )
            report_lines.append("\n")

    # Анализ зависимостей
    if dependency_results:
        report_lines.append("## Анализ зависимостей\n")
        report_lines.append(
            f"- **Проектов проверено:** {dependency_results.get('total_projects', 0)}\n"
        )
        report_lines.append(
            f"- **Конфликтов найдено:** {len(dependency_results.get('conflicts', []))}\n"
        )
        report_lines.append(
            f"- **Неиспользуемых зависимостей:** {len(dependency_results.get('unused_dependencies', []))}\n"
        )
        report_lines.append(
            f"- **Устаревших зависимостей:** {len(dependency_results.get('outdated_dependencies', []))}\n"
        )
        report_lines.append("\n")

        # Конфликты
        if dependency_results.get("conflicts"):
            report_lines.append("### Конфликты зависимостей\n")
            report_lines.append("| Проект | Сообщение |\n")
            report_lines.append("|--------|-----------|\n")
            for conflict in dependency_results["conflicts"][:20]:
                report_lines.append(
                    f"| `{conflict['project']}` | {conflict['message']} |\n"
                )
            report_lines.append("\n")

        # Неиспользуемые зависимости
        if dependency_results.get("unused_dependencies"):
            report_lines.append("### Неиспользуемые зависимости\n")
            report_lines.append("| Проект | Зависимость | Причина |\n")
            report_lines.append("|--------|-------------|----------|\n")
            for unused in dependency_results["unused_dependencies"][:20]:
                report_lines.append(
                    f"| `{unused['project']}` | {unused['dependency']} | {unused['reason']} |\n"
                )
            report_lines.append("\n")

    # Кэши
    if scan_results.get("caches"):
        report_lines.append("## Кэши\n")
        report_lines.append("| Путь | Размер |\n")
        report_lines.append("|------|--------|\n")
        for cache in scan_results["caches"][:20]:
            report_lines.append(f"| `{cache['path']}` | {cache['size_formatted']} |\n")
        report_lines.append("\n")

    # Остатки приложений
    if scan_results.get("orphaned_apps"):
        report_lines.append("## Возможные остатки удаленных приложений\n")
        report_lines.append("| Путь | Размер | Статус |\n")
        report_lines.append("|------|--------|--------|\n")
        for app in scan_results["orphaned_apps"][:20]:
            status = (
                "Возможно удалено" if app.get("possibly_orphaned") else "Приложение установлено"
            )
            report_lines.append(f"| `{app['path']}` | {app['size_formatted']} | {status} |\n")
        report_lines.append("\n")

    # Скрытые файлы
    if scan_results.get("hidden_files"):
        report_lines.append("## Большие скрытые файлы и директории\n")
        report_lines.append("| Путь | Тип | Размер |\n")
        report_lines.append("|------|-----|--------|\n")
        for hidden in scan_results["hidden_files"][:20]:
            report_lines.append(
                f"| `{hidden['path']}` | {hidden['type']} | {hidden['size_formatted']} |\n"
            )
        report_lines.append("\n")

    # Артефакты проектов
    if scan_results.get("project_artifacts"):
        report_lines.append("## Артефакты проектов\n")
        report_lines.append("| Тип | Количество | Общий размер |\n")
        report_lines.append("|-----|------------|--------------|\n")
        for artifact in scan_results["project_artifacts"]:
            report_lines.append(
                f"| `{artifact['type']}` | {artifact['count']} | {artifact['total_size_formatted']} |\n",
            )
        report_lines.append("\n")

    # Безопасность
    if security_results.get("issues"):
        report_lines.append("## Проблемы безопасности\n")
        report_lines.append("| Уровень | Категория | Путь | Описание |\n")
        report_lines.append("|---------|-----------|------|----------|\n")
        for issue in security_results["issues"]:
            report_lines.append(
                f"| **{issue['severity']}** | {issue['category']} | `{issue['path']}` | {issue['description']} |\n",
            )
        report_lines.append("\n")

    # Рекомендации по очистке
    if cleanup_analysis.get("recommendations"):
        report_lines.append("## Рекомендации по очистке\n")
        report_lines.append(
            f"**Потенциально можно освободить:** {cleanup_analysis['total_reclaimable_gb']:.2f} GB\n\n",
        )
        report_lines.append("| Тип | Путь | Размер | Риск | Описание |\n")
        report_lines.append("|-----|------|--------|------|----------|\n")
        for rec in cleanup_analysis["recommendations"][:30]:
            path = rec.get("path", rec.get("pattern", "N/A"))
            report_lines.append(
                f"| {rec['type']} | `{path}` | {rec.get('size_formatted', rec.get('total_size_formatted', 'N/A'))} | {rec['risk']} | {rec['description']} |\n",
            )
        report_lines.append("\n")

    return "".join(report_lines)


def generate_json_report(
    scan_results: dict[str, Any],
    security_results: dict[str, Any],
    cleanup_analysis: dict[str, Any],
    ml_cache_results: dict[str, Any] | None = None,
    dependency_results: dict[str, Any] | None = None,
    platform: str = "Unknown",
) -> str:
    """
    Сгенерировать JSON отчет.

    Args:
        scan_results: Результаты сканирования.
        security_results: Результаты проверки безопасности.
        cleanup_analysis: Анализ возможностей очистки.
        ml_cache_results: Результаты анализа ML кэшей.
        dependency_results: Результаты анализа зависимостей.
        platform: Платформа системы.

    Returns:
        JSON отчет в виде строки.
    """
    report = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform,
        "scan_results": scan_results,
        "security_results": security_results,
        "cleanup_analysis": cleanup_analysis,
    }

    if ml_cache_results:
        report["ml_cache_results"] = ml_cache_results

    if dependency_results:
        report["dependency_results"] = dependency_results

    return json.dumps(report, indent=2, ensure_ascii=False)


def save_report(
    report_content: str,
    output_path: Path,
    format_type: str = "markdown",
) -> None:
    """
    Сохранить отчет в файл.

    Args:
        report_content: Содержимое отчета.
        output_path: Путь для сохранения.
        format_type: Тип формата (markdown или json).

    Raises:
        ValueError: Если формат не поддерживается.
    """
    if format_type not in ["markdown", "json"]:
        raise ValueError(f"Неподдерживаемый формат: {format_type}")

    extension = ".md" if format_type == "markdown" else ".json"
    if not output_path.suffix == extension:
        output_path = output_path.with_suffix(extension)

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            f.write(report_content)
        logger.info(f"Отчет сохранен в {output_path}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении отчета: {e}")
        raise

