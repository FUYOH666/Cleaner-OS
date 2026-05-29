"""Recognizer plugin loader tests."""

from syscleaner.recognizers.plugins import load_plugin_recognizers


def test_load_plugins_empty_by_default() -> None:
    assert load_plugin_recognizers() == []
