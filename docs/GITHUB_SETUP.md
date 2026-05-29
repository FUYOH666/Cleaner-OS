# GitHub repository setup (maintainer)

After pushing v1.0.0, configure the repository **About** section on GitHub:

## Description (≤350 characters)

```
Trusted audit & tiered cleanup for dev workstations: ML caches, security, Python deps, AI-era IDE caches. macOS & Linux. Safe by default.
```

## Website

`https://scanovich.ai` or enable GitHub Pages from `/docs` if added later.

## Topics

```
python
macos
linux
cli
system-cleaner
security-audit
huggingface
cleanup-tool
ml-cache
typer
pydantic
uv
cursor
disk-space
developer-tools
sarif
open-source
```

## Social preview

Add `docs/assets/social-preview.png` (1200×630) — screenshot of `syscleaner scan --all` summary table — then set in **Settings → General → Social preview**.

## Release

```bash
git tag -a v1.0.0 -m "2026 Relaunch: tiered apply + AI-era recognizers"
git push origin v1.0.0
```

Copy notes from [CHANGELOG.md](../CHANGELOG.md) into the GitHub Release.

## Dependabot PRs

Open PRs #1 and #2 are dependency bumps — merge after CI passes on main.
