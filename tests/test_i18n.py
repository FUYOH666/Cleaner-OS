"""i18n tests."""

import pytest

from syscleaner.i18n import get_locale, set_locale, t


def test_default_locale_en() -> None:
    set_locale("en")
    assert get_locale() == "en"
    assert "Scan" in t("scan_summary")


def test_russian_locale() -> None:
    set_locale("ru")
    assert get_locale() == "ru"
    assert "Сводка" in t("scan_summary")


def test_invalid_locale() -> None:
    with pytest.raises(ValueError):
        set_locale("de")
