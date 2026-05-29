"""Configuration profiles (presets for recognizers and scan options)."""

from __future__ import annotations

from typing import Any

PROFILE_PRESETS: dict[str, dict[str, Any]] = {
    "default": {},
    "ml-workstation": {
        "recognizers": {
            "enabled": [
                "uv_cache",
                "hf_hub",
                "ollama",
                "pip_cache",
                "legacy_cache",
            ],
        },
        "scan": {"check_ml_cache": True, "check_dependencies": True},
    },
    "ios-dev": {
        "recognizers": {
            "enabled": [
                "xcode_derived",
                "xcode_archives",
                "homebrew_cache",
                "npm_cache",
                "orphaned_app_support",
            ],
        },
    },
    "minimal": {
        "recognizers": {
            "enabled": ["uv_cache", "pip_cache", "legacy_cache"],
        },
        "scan": {
            "check_security": False,
            "check_dependencies": False,
            "check_ml_cache": False,
        },
    },
}


def merge_profile(base: dict[str, Any], profile_name: str) -> dict[str, Any]:
    """Deep-merge profile preset into config dict (profile keys override base)."""
    preset = PROFILE_PRESETS.get(profile_name)
    if not preset:
        return base
    merged = dict(base)
    for key, value in preset.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged
