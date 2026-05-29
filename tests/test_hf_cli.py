"""Hugging Face CLI enrichment tests."""

from unittest.mock import MagicMock, patch

from syscleaner.hf_cli import enrich_ml_cache_results, fetch_hf_cache_listing


def test_fetch_hf_cache_missing_cli() -> None:
    with patch("syscleaner.hf_cli.shutil.which", return_value=None):
        assert fetch_hf_cache_listing() is None


def test_enrich_ml_cache_results_json() -> None:
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '[{"repo": "org/model"}]'
    with patch("syscleaner.hf_cli.shutil.which", return_value="/usr/bin/hf"):
        with patch("syscleaner.hf_cli.subprocess.run", return_value=mock_result):
            enriched = enrich_ml_cache_results({"total_models": 1})
    assert "hf_cli" in enriched
    assert enriched["hf_cli"]["entry_count"] == 1
