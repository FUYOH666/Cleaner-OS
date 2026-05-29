"""Configuration profile tests."""

from syscleaner.config import load_config
from syscleaner.profiles import merge_profile


def test_merge_profile_ml_workstation() -> None:
    base = {"profile": "ml-workstation", "scan": {"min_size_mb": 5}}
    merged = merge_profile(base, "ml-workstation")
    assert "hf_hub" in merged["recognizers"]["enabled"]
    assert merged["scan"]["check_ml_cache"] is True


def test_unknown_profile_passthrough() -> None:
    base = {"profile": "custom", "scan": {"min_size_mb": 10}}
    assert merge_profile(base, "custom") == base


def test_load_config_with_profile(tmp_path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
profile: minimal
scan:
  min_size_mb: 25
""",
    )
    settings = load_config(config_file)
    assert settings.profile == "minimal"
    assert settings.scan.check_security is False
    assert "uv_cache" in settings.recognizers.enabled
