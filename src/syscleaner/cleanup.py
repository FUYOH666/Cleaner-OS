"""Модуль анализа и очистки мусора."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def analyze_cleanup_opportunities(
    scan_results: dict[str, Any],
    ml_cache_results: dict[str, Any] | None = None,
    safe_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """
    Проанализировать возможности очистки.

    Args:
        scan_results: Результаты сканирования.
        ml_cache_results: Результаты анализа ML кэшей.
        safe_patterns: Паттерны безопасных для удаления файлов.

    Returns:
        Словарь с рекомендациями по очистке.
    """
    recommendations: list[dict[str, Any]] = []
    total_reclaimable_mb = 0.0

    # Анализ ML кэшей
    if ml_cache_results:
        unused_size_gb = ml_cache_results.get("unused_size_gb", 0)
        if unused_size_gb > 0:
            unused_size_mb = unused_size_gb * 1024
            recommendations.append(
                {
                    "type": "ml_cache",
                    "description": f"Неиспользуемые ML модели ({ml_cache_results.get('unused_models_count', 0)} штук)",
                    "size_mb": unused_size_mb,
                    "size_formatted": f"{unused_size_gb:.2f} GB",
                    "action": "delete",
                    "risk": "low",
                },
            )
            total_reclaimable_mb += unused_size_mb

    # Анализ кэшей
    if "caches" in scan_results:
        for cache in scan_results["caches"]:
            if cache["size_mb"] >= 50:  # Кэши больше 50MB
                recommendations.append(
                    {
                        "type": "cache",
                        "path": cache["path"],
                        "name": cache["name"],
                        "size_mb": cache["size_mb"],
                        "size_formatted": cache["size_formatted"],
                        "action": "delete",
                        "risk": "low",
                        "description": f"Большой кэш приложения {cache['name']}",
                    },
                )
                total_reclaimable_mb += cache["size_mb"]

    # Анализ артефактов проектов
    if "project_artifacts" in scan_results:
        for artifact in scan_results["project_artifacts"]:
            recommendations.append(
                {
                    "type": "project_artifact",
                    "pattern": artifact["type"],
                    "count": artifact["count"],
                    "total_size_mb": artifact["total_size_mb"],
                    "total_size_formatted": artifact["total_size_formatted"],
                    "action": "delete",
                    "risk": "low",
                    "description": f"{artifact['count']} артефактов типа {artifact['type']}",
                },
            )
            total_reclaimable_mb += artifact["total_size_mb"]

    # Анализ корзины
    if "trash" in scan_results and scan_results["trash"]["size_mb"] > 0:
        recommendations.append(
            {
                "type": "trash",
                "path": scan_results["trash"]["path"],
                "count": scan_results["trash"]["count"],
                "size_mb": scan_results["trash"]["size_mb"],
                "size_formatted": scan_results["trash"]["size_formatted"],
                "action": "empty",
                "risk": "low",
                "description": "Очистка корзины",
            },
        )
        total_reclaimable_mb += scan_results["trash"]["size_mb"]

    # Анализ логов
    if "logs" in scan_results:
        for log in scan_results["logs"]:
            if log["size_mb"] >= 100:  # Логи больше 100MB
                recommendations.append(
                    {
                        "type": "log",
                        "path": log["path"],
                        "name": log["name"],
                        "size_mb": log["size_mb"],
                        "size_formatted": log["size_formatted"],
                        "action": "delete",
                        "risk": "low",
                        "description": f"Большой лог {log['name']}",
                    },
                )
                total_reclaimable_mb += log["size_mb"]

    return {
        "recommendations": recommendations,
        "total_reclaimable_mb": total_reclaimable_mb,
        "total_reclaimable_gb": total_reclaimable_mb / 1024,
        "total_items": len(recommendations),
    }

