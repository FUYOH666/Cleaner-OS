# Technical review log (2026-05-29)

Offline review before v1.0.0 release. Status: **addressed in main**.

## Findings and resolutions

| Area | Issue | Resolution |
|------|--------|------------|
| Release | v1.0 code uncommitted on `main` | Committed, tagged `v1.0.0`, pushed |
| Docs | `scripts/README.md` referenced non-existent Wi-Fi scripts | Rewritten; only existing `.example` scripts |
| Tooling | `pyright` missing from dev deps | Added to `dependency-groups.dev`; CI job added |
| Config | `profile` field unused | Implemented `profiles.py` presets |
| CLI | No `healthz` alias | Added `syscleaner healthz` |
| CLI | No JSON Schema export | Added `syscleaner export-schema` |
| Recognizers | Docker missing from clean-m1 parity | Added `docker_cache` recognizer |
| Git | `*.json` in `.gitignore` too broad | Narrowed to scan output patterns |
| GitHub | Empty About / topics | Updated via `gh` API |
| Tests | Russian docstrings in tests | English in `tests/` |
| Classifier | Beta while shipping 1.0 | Production/Stable |

## Remaining (non-blocking)

- **Russian docstrings** in legacy `scanner/` and `platform/` modules (internal; does not affect CLI UX).
- **Social preview image** — add `docs/assets/social-preview.png` manually (see `docs/assets/README.md`).
- **Dependabot PRs #1/#2** — rebase or close after CI on `main` passes; may be superseded by `uv.lock` bump in v1.0.
- **PyPI publish** — optional; install via `uv tool install git+...` documented in README.
- **Phase 2 plan items** (TUI, MCP, i18n) — deferred to v1.1+.

## Quality gate (local)

```bash
uv sync --all-groups
uv run ruff check .
uv run pyright
uv run pytest -q
```

Last run: 19 tests passed, 0 pyright errors.
