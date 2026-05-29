# Changelog

All notable changes to this project are documented in this file.

## [1.2.1] - 2026-05-29

### Added

- TUI safe-tier execute with double confirmation (`execute_safe_plan`)
- Report section headers i18n (EN/RU) for all major H2 blocks
- 70 tests; coverage CI gate at 60% on measured core
- [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md), [docs/PYPI_DEFERRED.md](docs/PYPI_DEFERRED.md)

### Changed

- PyPI classifier: **Beta** until package is published
- Branch protection docs aligned with CI matrix check names

### Project

- **Feature-complete** for v1.2.x; maintenance mode (security fixes)

## [1.2.0] - 2026-05-29

### Added

- Duplicate file finder: `syscleaner scan --duplicates`
- Recognizer plugin entry points (`syscleaner.recognizers`)
- MCP `apply_plan_tool` with `allow_execute` gate
- GitHub composite Action (`.github/actions/scan`) + `examples/workflow-sarif.yml`
- Homebrew formula example (`docs/homebrew/syscleaner.rb`)
- Coverage + Bandit in CI; 48+ tests with golden `tests/fixtures/scan_sample.json`

### Changed

- Full RU i18n for `health`; report headers localized via `SYSCLEANER_LANG`
- `.env` wired: `LOG_LEVEL`, `SYSCLEANER_LANG` via pydantic-settings
- Narrower exception handling in apply/registry/config
- Reporter fix: no shadowing of i18n `t()`

## [1.1.1] - 2026-05-29

### Fixed

- CI extras: `syscleaner --lang ru health` flag order
- `SYSCLEANER_LANG` applied at CLI startup

## [1.1.0] - 2026-05-29

### Added

- CLI i18n: `--lang en|ru` and `SYSCLEANER_LANG`
- Optional extras: `tui` (Textual), `mcp` (MCP server with `syscleaner-mcp`)
- Hugging Face CLI enrichment via `hf cache ls` when available
- PyPI publishing workflow (tag `v*` triggers publish)
- Social preview image in `docs/assets/`

### Changed

- All legacy `src/` docstrings in English; CI blocks Cyrillic in `src/`
- Russian changelog archived to `docs/history/CHANGELOG-legacy-ru.md`

## [1.0.1] - 2026-05-29

### Changed

- All `src/` docstrings, comments, and log messages in English
- CI gate: fail if Cyrillic appears under `src/`
- Legacy Russian changelog moved to [docs/history/CHANGELOG-legacy-ru.md](docs/history/CHANGELOG-legacy-ru.md)
- Dependabot removed; dev dependencies consolidated in `dependency-groups.dev`

### Added

- Branch protection documentation for `main`
- Social preview asset under `docs/assets/`

## [1.0.0] - 2026-05-29

### Added

- **Pydantic scan bundle** (`schema_version` 1.0) for `--save-results` JSON
- **Recognizer plugins**: uv, Cursor, Hugging Face hub, Ollama, Playwright, Xcode, npm, Homebrew, pip, orphaned App Support
- **`syscleaner plan`** — cleanup plan with risk tiers and optional `--target-gb` budget
- **`syscleaner apply`** — tiered cleanup with dry-run default, `--execute`, `--allow-risky`
- **`syscleaner export-sarif`** — SARIF 2.1.0 for security findings (CI / Code Scanning)
- Native CLI delegation: `uv cache prune`, `hf cache prune`, `brew cleanup -s`, `npm cache clean`
- `docs/PRODUCT.md`, `docs/migration-from-cleanmac.md`, `examples/com.syscleaner.weekly.plist`
- GitHub Actions CI (macOS + Ubuntu, Python 3.12/3.13)
- Expanded pytest suite (models, recognizers, apply, SARIF)

### Changed

- Version bump to 1.0.0; positioning: trusted audit + tiered cleanup
- `cleanup.py` refactored; plan logic in `plan_builder.py`
- README restructured (commercial CTA moved to `docs/COMMERCIAL.md`)

### Security

- Apply never runs risky actions without `--allow-risky`
- Delete paths require explicit `--execute` and confirmation

### Housekeeping (post-release polish)

- Configuration profiles: `default`, `ml-workstation`, `ios-dev`, `minimal`
- `syscleaner healthz` alias, `export-schema` command, Docker recognizer
- Removed obsolete Wi-Fi script docs from `scripts/README.md`
- Dev tooling: pyright + ruff in `dependency-groups.dev`, CI pyright job
- `GOVERNANCE.md`, English test suite docstrings, production/stable classifier

## [0.3.0] - 2026-02-26

### Added

- Python 3.13 support in CI matrix
- English localization for CLI output and reports

### Changed

- **Dependencies:** Upgraded Typer (>=0.15), Ruff (>=0.9), Pyright (>=1.1.400), PyYAML (>=6.0.2)
- **Removed:** `tomli` dependency (Python 3.12+ uses stdlib `tomllib`)
- **Python:** `requires-python` set to `>=3.12,<3.15`
- **Pre-commit:** Updated Ruff to v0.9, Pyright to v1.1.400, Bandit to 1.8.3
- All user-facing strings translated to English
- `config.yaml.example` comments translated to English
- README: removed duplicate badges, updated Python requirement to 3.12+

### Removed

- `config.yaml` from repository (user config; use `config.yaml.example` as template)

## Older releases

Detailed notes for v0.2.x and v0.1.0 (Russian) are archived in [docs/history/CHANGELOG-legacy-ru.md](docs/history/CHANGELOG-legacy-ru.md).

[1.2.1]: https://github.com/FUYOH666/Cleaner-OS/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/FUYOH666/Cleaner-OS/compare/v1.1.0...v1.2.0
[1.1.1]: https://github.com/FUYOH666/Cleaner-OS/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/FUYOH666/Cleaner-OS/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/FUYOH666/Cleaner-OS/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/FUYOH666/Cleaner-OS/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/FUYOH666/Cleaner-OS/compare/v0.2.1...v0.3.0
[0.2.0]: https://github.com/FUYOH666/Cleaner-OS/compare/v0.1.0...v0.2.0
