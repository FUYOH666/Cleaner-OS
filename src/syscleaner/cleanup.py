"""Cleanup analysis — backwards-compatible wrapper."""

from typing import Any

from syscleaner.plan_builder import legacy_cleanup_to_findings


def analyze_cleanup_opportunities(
    scan_results: dict[str, Any],
    ml_cache_results: dict[str, Any] | None = None,
    safe_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """
    Analyze cleanup opportunities from scan results.

    Returns legacy dict format for reports; findings also available via ScanBundle.
    """
    recommendations: list[dict[str, Any]] = []
    total_reclaimable_mb = 0.0

    if ml_cache_results:
        unused_size_gb = ml_cache_results.get("unused_size_gb", 0)
        if unused_size_gb > 0:
            unused_size_mb = unused_size_gb * 1024
            n_unused = ml_cache_results.get("unused_models_count", 0)
            recommendations.append(
                {
                    "type": "ml_cache",
                    "description": f"Unused ML models ({n_unused})",
                    "size_mb": unused_size_mb,
                    "size_formatted": f"{unused_size_gb:.2f} GB",
                    "action": "delete",
                    "risk": "low",
                },
            )
            total_reclaimable_mb += unused_size_mb

    if "caches" in scan_results:
        for cache in scan_results["caches"]:
            if cache["size_mb"] >= 50:
                recommendations.append(
                    {
                        "type": "cache",
                        "path": cache["path"],
                        "name": cache["name"],
                        "size_mb": cache["size_mb"],
                        "size_formatted": cache["size_formatted"],
                        "action": "delete",
                        "risk": "low",
                        "description": f"Large app cache: {cache['name']}",
                    },
                )
                total_reclaimable_mb += cache["size_mb"]

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
                    "risk": "medium",
                    "description": f"{artifact['count']} artifacts of type {artifact['type']}",
                },
            )
            total_reclaimable_mb += artifact["total_size_mb"]

    if "trash" in scan_results and scan_results["trash"].get("size_mb", 0) > 0:
        recommendations.append(
            {
                "type": "trash",
                "path": scan_results["trash"]["path"],
                "count": scan_results["trash"]["count"],
                "size_mb": scan_results["trash"]["size_mb"],
                "size_formatted": scan_results["trash"]["size_formatted"],
                "action": "empty",
                "risk": "low",
                "description": "Empty trash",
            },
        )
        total_reclaimable_mb += scan_results["trash"]["size_mb"]

    if "logs" in scan_results:
        for log in scan_results["logs"]:
            if log["size_mb"] >= 100:
                recommendations.append(
                    {
                        "type": "log",
                        "path": log["path"],
                        "name": log["name"],
                        "size_mb": log["size_mb"],
                        "size_formatted": log["size_formatted"],
                        "action": "delete",
                        "risk": "low",
                        "description": f"Large log: {log['name']}",
                    },
                )
                total_reclaimable_mb += log["size_mb"]

    return {
        "recommendations": recommendations,
        "total_reclaimable_mb": total_reclaimable_mb,
        "total_reclaimable_gb": total_reclaimable_mb / 1024,
        "total_items": len(recommendations),
    }


__all__ = ["analyze_cleanup_opportunities", "legacy_cleanup_to_findings"]
