# Technical review log

## v1.2.0 (2026-05-29) — Staff Max wave

- Credibility: LOG_LEVEL/.env, full health i18n, PyPI badge (after publish)
- Engineering: pytest-cov gate (50%+ measured core), bandit CI, 48 tests
- Product: `--duplicates`, GitHub Action, MCP apply gated, plugin entry points
- Docs: Homebrew formula example, workflow-sarif example

## Backlog (v1.3+)

- Markdown report full i18n (gettext)
- App uninstaller
- Homebrew tap (live)
- GitHub Discussions
- Coverage target 70%+ on full tree

## Quality gate

```bash
uv sync --all-groups --all-extras
uv run ruff check .
uv run pyright
uv run pytest -q
! rg '[А-Яа-яЁё]' src/
```
