# System Cleaner — Product Brief

## Mission

Free, open-source CLI that helps developers and power users **understand** what consumes disk space and **fix security issues** on macOS and Linux — without surprise deletions.

## Principles

1. **No silent delete** — scan and report by default; cleanup requires explicit `apply` with dry-run first.
2. **Tiered risk** — every reclaimable item is `safe`, `moderate`, or `risky`; risky actions need `--allow-risky`.
3. **Native tools first** — prefer `uv cache prune`, `hf cache prune`, `brew cleanup` over raw `rm` for package-manager caches.
4. **Explicit degradation** — missing binaries are logged; findings stay in the report as manual actions.
5. **RAG-first reporting** — structured JSON (Pydantic) for automation; Markdown and SARIF for humans and CI.

## Audience

- ML / AI developers (Hugging Face, PyTorch, Ollama caches)
- Full-stack developers (node_modules, Xcode, Docker, uv, Cursor)
- Anyone who outgrew generic cleaners (CleanMyMac) for dev-specific junk

## v1.1 capabilities

- **i18n**: English (default) and Russian CLI via `--lang` / `SYSCLEANER_LANG`
- **TUI** (optional): Textual UI over saved scan JSON
- **MCP** (optional): `scan_summary`, `export_plan`, `health`; `apply_plan_tool` only with `allow_execute=true`
- **PyPI**: `pip install syscleaner` (after trusted-publisher setup on PyPI)

## Non-goals (v1.x)

- Duplicate-file finder, app uninstaller UI, Windows support
- Full gettext / localized Markdown reports (v1.2+)
- Automatic scheduled deletion (weekly jobs should scan + report only)

## Commercial support

Optional professional deployment is documented in [COMMERCIAL.md](COMMERCIAL.md), separate from the OSS README.
