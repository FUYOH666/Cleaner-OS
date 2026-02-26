"""Cross-platform report generation module."""

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
    report_lines.append(f"**Platform:** {platform}\n")
    report_lines.append(f"**Scan date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    report_lines.append("## Summary\n")
    total_size_mb = (
        sum(item["size_mb"] for item in scan_results.get("caches", []))
        + sum(item["size_mb"] for item in scan_results.get("orphaned_apps", []))
        + sum(item["size_mb"] for item in scan_results.get("hidden_files", []))
    )
    report_lines.append(
        f"- **Total data size:** {total_size_mb:.2f} MB ({total_size_mb / 1024:.2f} GB)\n"
    )

    if ml_cache_results:
        report_lines.append("## ML Model Caches\n")
        report_lines.append(f"- **Total models:** {ml_cache_results.get('total_models', 0)}\n")
        report_lines.append(
            f"- **Total size:** {ml_cache_results.get('total_size_gb', 0):.2f} GB\n"
        )
        report_lines.append(
            f"- **Unused models:** {ml_cache_results.get('unused_models_count', 0)}\n"
        )
        report_lines.append(
            f"- **Unused size:** {ml_cache_results.get('unused_size_gb', 0):.2f} GB\n"
        )
        report_lines.append("\n")

        # Детали по типам кэшей
        if ml_cache_results.get("models_by_type"):
            report_lines.append("### By cache type\n")
            report_lines.append("| Type | Count | Size |\n")
            report_lines.append("|-----|------------|--------|\n")
            for cache_type, models in ml_cache_results["models_by_type"].items():
                total_size = sum(m["size_gb"] for m in models)
                report_lines.append(f"| {cache_type} | {len(models)} | {total_size:.2f} GB |\n")
            report_lines.append("\n")

        # Топ моделей по размеру
        if ml_cache_results.get("models"):
            report_lines.append("### Top models by size\n")
            report_lines.append("| Model | Size | Type |\n")
            report_lines.append("|--------|--------|-----|\n")
            for model in ml_cache_results["models"][:10]:
                report_lines.append(
                    f"| {model['name']} | {model['size_gb']:.2f} GB | {model['cache_type']} |\n"
                )
            report_lines.append("\n")

    if dependency_results:
        report_lines.append("## Dependency Analysis\n")
        report_lines.append(
            f"- **Projects checked:** {dependency_results.get('total_projects', 0)}\n"
        )
        report_lines.append(f"- **Conflicts:** {len(dependency_results.get('conflicts', []))}\n")
        report_lines.append(
            f"- **Unused dependencies:** {len(dependency_results.get('unused_dependencies', []))}\n"
        )
        n_outdated = len(dependency_results.get("outdated_dependencies", []))
        report_lines.append(f"- **Outdated dependencies:** {n_outdated}\n")
        report_lines.append("\n")

        # Конфликты
        if dependency_results.get("conflicts"):
            report_lines.append("### Dependency Conflicts\n")
            report_lines.append("| Project | Message |\n")
            report_lines.append("|--------|-----------|\n")
            for conflict in dependency_results["conflicts"][:20]:
                report_lines.append(f"| `{conflict['project']}` | {conflict['message']} |\n")
            report_lines.append("\n")

        # Неиспользуемые зависимости
        if dependency_results.get("unused_dependencies"):
            report_lines.append("### Unused Dependencies\n")
            report_lines.append("| Project | Dependency | Reason |\n")
            report_lines.append("|--------|-------------|----------|\n")
            for unused in dependency_results["unused_dependencies"][:20]:
                report_lines.append(
                    f"| `{unused['project']}` | {unused['dependency']} | {unused['reason']} |\n"
                )
            report_lines.append("\n")

    if scan_results.get("caches"):
        report_lines.append("## Caches\n")
        report_lines.append("| Path | Size |\n")
        report_lines.append("|------|--------|\n")
        for cache in scan_results["caches"][:20]:
            report_lines.append(f"| `{cache['path']}` | {cache['size_formatted']} |\n")
        report_lines.append("\n")

    if scan_results.get("orphaned_apps"):
        report_lines.append("## Possible App Leftovers\n")
        report_lines.append("| Path | Size | Status |\n")
        report_lines.append("|------|--------|--------|\n")
        for app in scan_results["orphaned_apps"][:20]:
            status = "Possibly removed" if app.get("possibly_orphaned") else "App installed"
            report_lines.append(f"| `{app['path']}` | {app['size_formatted']} | {status} |\n")
        report_lines.append("\n")

    if scan_results.get("hidden_files"):
        report_lines.append("## Large Hidden Files\n")
        report_lines.append("| Path | Type | Size |\n")
        report_lines.append("|------|-----|--------|\n")
        for hidden in scan_results["hidden_files"][:20]:
            report_lines.append(
                f"| `{hidden['path']}` | {hidden['type']} | {hidden['size_formatted']} |\n"
            )
        report_lines.append("\n")

    if scan_results.get("project_artifacts"):
        report_lines.append("## Project Artifacts\n")
        report_lines.append("| Type | Count | Total Size |\n")
        report_lines.append("|-----|------------|--------------|\n")
        for artifact in scan_results["project_artifacts"]:
            t, c, s = artifact["type"], artifact["count"], artifact["total_size_formatted"]
            report_lines.append(f"| `{t}` | {c} | {s} |\n")
        report_lines.append("\n")

    if security_results.get("issues"):
        report_lines.append("## Security Issues\n")

        high_issues = [i for i in security_results["issues"] if i.get("severity") == "high"]
        medium_issues = [i for i in security_results["issues"] if i.get("severity") == "medium"]
        low_issues = [i for i in security_results["issues"] if i.get("severity") == "low"]

        if high_issues:
            report_lines.append("### Critical (high)\n")
            report_lines.append(
                "| Category | Path | Description | Why critical | Recommendation |\n"
            )
            report_lines.append(
                "|----------|------|-------------|--------------|----------------|\n"
            )
            for issue in high_issues:
                why_critical = ""
                category_lower = issue.get("category", "").lower()
                if "ssh" in category_lower:
                    why_critical = "Wrong permissions may allow attackers to access servers"
                elif "permission" in category_lower or "file" in category_lower:
                    why_critical = "Overly open permissions may leak confidential data"
                elif "sensitive" in category_lower:
                    why_critical = "Files with secrets may be compromised in a data leak"
                else:
                    why_critical = "Requires immediate attention to prevent data leak"

                recommendation = issue.get("recommendation", "N/A")
                report_lines.append(
                    f"| {issue['category']} | `{issue['path']}` | {issue['description']} | "
                    f"{why_critical} | {recommendation} |\n",
                )
            report_lines.append("\n")

        if medium_issues:
            report_lines.append("### Medium\n")
            report_lines.append("| Category | Path | Description | Recommendation |\n")
            report_lines.append("|-----------|------|----------|--------------|\n")
            for issue in medium_issues:
                rec = issue.get("recommendation", "N/A")
                cat, path, desc = issue["category"], issue["path"], issue["description"]
                report_lines.append(f"| {cat} | `{path}` | {desc} | {rec} |\n")
            report_lines.append("\n")

        if low_issues:
            report_lines.append("### Low\n")
            report_lines.append("| Category | Path | Description | Recommendation |\n")
            report_lines.append("|-----------|------|----------|--------------|\n")
            for issue in low_issues:
                rec = issue.get("recommendation", "N/A")
                cat, path, desc = issue["category"], issue["path"], issue["description"]
                report_lines.append(f"| {cat} | `{path}` | {desc} | {rec} |\n")
            report_lines.append("\n")

    if cleanup_analysis.get("recommendations"):
        report_lines.append("## Cleanup Recommendations\n")
        report_lines.append(
            f"**Potentially reclaimable:** {cleanup_analysis['total_reclaimable_gb']:.2f} GB\n\n",
        )
        report_lines.append("| Type | Path | Size | Risk | Description |\n")
        report_lines.append("|-----|------|--------|------|----------|\n")
        for rec in cleanup_analysis["recommendations"][:30]:
            path = rec.get("path", rec.get("pattern", "N/A"))
            size = rec.get("size_formatted", rec.get("total_size_formatted", "N/A"))
            report_lines.append(
                f"| {rec['type']} | `{path}` | {size} | {rec['risk']} | {rec['description']} |\n"
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
        raise ValueError(f"Unsupported format: {format_type}")

    extension = ".md" if format_type == "markdown" else ".json"
    if not output_path.suffix == extension:
        output_path = output_path.with_suffix(extension)

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            f.write(report_content)
        logger.info("Report saved to %s", output_path)
    except Exception as e:
        logger.error("Error saving report: %s", e)
        raise
