"""Settings and logging from environment."""

from pytest import MonkeyPatch

from syscleaner.config import Settings, configure_logging


def test_log_level_from_env(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    settings = Settings()
    assert settings.log_level == "WARNING"


def test_configure_logging_invalid_falls_back() -> None:
    configure_logging("NOT_A_LEVEL")
    import logging

    assert logging.getLogger().level <= logging.WARNING
