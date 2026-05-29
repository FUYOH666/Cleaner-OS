# Technical review log

## Project closed — 2026-05-29 (v1.2.1)

Cleaner-OS is **feature-complete** for the v1.2 scope. Further work is maintenance-only unless v2 is scoped.

| Area | State |
|------|--------|
| Tests | 70+, coverage gate 60% (measured core) |
| CI | Matrix + Bandit + Cyrillic gate |
| PyPI | Deferred — [PYPI_DEFERRED.md](PYPI_DEFERRED.md) |
| Docs | [PROJECT_STATUS.md](PROJECT_STATUS.md) |

## v1.2.0 — Staff Max

- i18n, duplicates, GitHub Action, MCP apply gated, plugin entry points

## Backlog (v2+)

- Coverage 70%+ on full tree (incl. CLI `main.py` integration tests)
- Markdown report full gettext
- App uninstaller
- Live Homebrew tap
- HTTP daemon (only if needed)

## Quality gate

```bash
uv sync --all-groups --all-extras
uv run ruff check .
uv run pyright
uv run pytest -q
! rg '[А-Яа-яЁё]' src/
```
