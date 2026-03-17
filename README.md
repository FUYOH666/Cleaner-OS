# System Cleaner

**Reclaim dozens of gigabytes and fix security risks — one scan instead of manual hunting.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/FUYOH666/Cleaner-OS)

---

## The Problem

Your disk fills up with caches and old ML models — you don't know what's safe to delete. Dependency conflicts and outdated packages take hours to track down manually. Sensitive files and wrong SSH permissions hide in plain sight, with no clear warning until it's too late.

## The Solution

One scan finds caches, unused ML models, project artifacts, and security issues. You get recommendations with size estimates — see exactly how much you can reclaim. Reports in Markdown or JSON for automation and compliance.

## Results

- **Before:** Manual hunting through `~/.cache`, `~/Library/Caches`, Hugging Face hub — hours spent, uncertainty about what to delete.
- **After:** Single command, structured report. Typical ML workstations: 50–100+ GB reclaimable. Dependency conflicts and security issues surfaced in minutes.

---

## Quick Start

```bash
git clone https://github.com/FUYOH666/Cleaner-OS.git
cd Cleaner-OS
uv sync
uv run syscleaner scan --all
```

Run directly: `syscleaner` or `system-cleaner`

```bash
# Full scan
syscleaner scan --all

# By category
syscleaner scan --caches
syscleaner scan --security
syscleaner scan --projects
syscleaner scan --dependencies
syscleaner scan --ml-cache

# Save and report
syscleaner scan --all --save-results results.json
syscleaner report --format markdown --output report.md --from-scan results.json

# Health check
syscleaner health
```

---

## Deploy This For Your Business

This is an open-source project. You can run it yourself.

Or I can deploy, customize, and integrate it for your company in **2 weeks**.

**Fixed price: $2,000** — includes data setup, customization, deployment, and 30 days of support.

- **Email:** iamfuyoh@gmail.com
- **Telegram:** [@ScanovichAI](https://t.me/ScanovichAI)

---

## Tech Stack

- **Python 3.12+** with uv
- **Platforms:** macOS, Linux

**What it scans:**

1. Caches — `~/Library/Caches/` (macOS), `~/.cache/` (Linux)
2. App leftovers — Application Support vs installed apps
3. Security — SSH permissions, sensitive files, world-readable configs
4. Hidden files — Large hidden files/dirs in home
5. Project artifacts — `__pycache__`, `node_modules`, `dist`, `build`
6. ML caches — Hugging Face, PyTorch, TensorFlow (unused models >30 days)
7. Dependencies — Conflicts, unused, outdated via `uv pip check`

**Configuration:** Copy `config.yaml.example` to `config.yaml`. Optional; defaults work out of the box.

**Reports:** Markdown (summary, recommendations) or JSON (automation).

**Security:** No automatic deletions — analysis and recommendations only. Fail-fast on config errors.

---

## Contributing

1. Fork, create branch, make changes
2. Run `uv run ruff check .`, `uv run pyright`, `uv run pytest`
3. Open Pull Request

## License

MIT. See [LICENSE](LICENSE).

## Author

Aleksandr Mordvinov — [GitHub](https://github.com/FUYOH666) | [scanovich.ai](https://scanovich.ai)
