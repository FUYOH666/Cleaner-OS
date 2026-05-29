"""Locale resolution and message lookup."""

from __future__ import annotations

import os

from syscleaner.i18n.messages_en import MESSAGES as EN
from syscleaner.i18n.messages_ru import MESSAGES as RU

_LOCALE = "en"
_CATALOGS = {"en": EN, "ru": RU}


def get_locale() -> str:
    return _LOCALE


def set_locale(lang: str | None) -> None:
    global _LOCALE
    if lang is None:
        lang = os.environ.get("SYSCLEANER_LANG", "en")
    normalized = lang.lower().strip()[:2]
    if normalized not in _CATALOGS:
        raise ValueError(f"Unsupported language: {lang}")
    _LOCALE = normalized


def t(key: str, **kwargs: object) -> str:
    catalog = _CATALOGS.get(_LOCALE, EN)
    template = catalog.get(key, EN.get(key, key))
    if kwargs:
        return template.format(**kwargs)
    return template
