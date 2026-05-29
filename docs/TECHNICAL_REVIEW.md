# Technical review log

## v1.1.0 (2026-05-29) — complete

All items from the v1.0.1 / v1.1.0 finish plan are implemented:

- English-only `src/` with CI Cyrillic gate
- i18n (`en` / `ru`), TUI and MCP optional extras
- HF CLI cache enrichment, PyPI publish workflow
- Branch protection documented, social preview asset
- Legacy Russian changelog archived

## Backlog (v1.2+)

- Markdown report i18n (gettext)
- Duplicate finder / app uninstaller
- Homebrew tap
- GitHub Discussions

## Quality gate

```bash
uv sync --all-groups --all-extras
uv run ruff check .
uv run pyright
uv run pytest -q
! rg '[А-Яа-яЁё]' src/
```
