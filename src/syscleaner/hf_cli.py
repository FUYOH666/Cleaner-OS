"""Optional Hugging Face CLI cache enrichment."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def fetch_hf_cache_listing() -> dict[str, Any] | None:
    """
    Run `hf cache ls` when the Hugging Face CLI is available.

    Returns:
        Parsed metadata dict or None if CLI is missing or fails.
    """
    if not shutil.which("hf"):
        logger.info("hf CLI not found; skipping hf cache ls enrichment")
        return None

    try:
        result = subprocess.run(
            ["hf", "cache", "ls", "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if result.returncode != 0:
            # Fallback without --json if older hf version
            result = subprocess.run(
                ["hf", "cache", "ls"],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            if result.returncode != 0:
                logger.warning("hf cache ls failed: %s", result.stderr.strip())
                return None
            return {
                "source": "hf_cli",
                "format": "text",
                "stdout": result.stdout.strip(),
                "entry_count": len(
                    [line for line in result.stdout.splitlines() if line.strip()],
                ),
            }

        data = json.loads(result.stdout)
        if isinstance(data, list):
            return {"source": "hf_cli", "format": "json", "entries": data, "entry_count": len(data)}
        return {"source": "hf_cli", "format": "json", "data": data}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        logger.warning("hf cache ls enrichment error: %s", e)
        return None


def enrich_ml_cache_results(results: dict[str, Any]) -> dict[str, Any]:
    """Attach hf CLI listing to ML cache scan results when available."""
    hf_data = fetch_hf_cache_listing()
    if hf_data:
        results["hf_cli"] = hf_data
    return results
