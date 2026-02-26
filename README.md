# System Cleaner

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/FUYOH666/Cleaner-OS)

Universal CLI for system cleanup and audit. Analyzes ML caches, Python dependencies, application leftovers, and security on macOS and Linux.

## Problems Solved

- Unused ML models (Hugging Face, PyTorch, TensorFlow) consuming disk space
- Dependency conflicts in Python projects
- Removed application leftovers
- Security issues (file permissions, secrets in code)
- Build artifacts and unused dependencies

## Features

- System scanning: caches, logs, application leftovers
- ML cache analysis: Hugging Face, PyTorch, TensorFlow
- Dependency analysis: conflicts, unused, outdated
- Security checks: permissions, SSH keys, sensitive files
- Cleanup recommendations with size estimates
- Cross-platform: macOS and Linux
- Reports: Markdown and JSON

## Requirements

- Python 3.12+ (3.12, 3.13)
- uv (installed automatically)
- macOS or Linux

## Installation

```bash
git clone https://github.com/FUYOH666/Cleaner-OS.git
cd Cleaner-OS
uv sync
uv run python -m syscleaner health
```

Run directly: `syscleaner` or `system-cleaner`

## Usage

```bash
# Full scan
syscleaner scan --all

# Categories
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

## Configuration

Copy `config.yaml.example` to `config.yaml` and edit. Optional; defaults work out of the box.

```yaml
scan:
  exclude_paths: [~/Library/Mail/, ~/Library/Messages/, ...]
  min_size_mb: 10
  check_security: true
  check_project_artifacts: true
  check_dependencies: true
  check_ml_cache: true

security:
  sensitive_patterns: ["*.env", "*credentials*", ...]
  check_ssh_permissions: true
  check_file_permissions: true

cleanup:
  safe_to_delete_patterns: ["**/__pycache__", "**/.DS_Store", ...]
```

## What It Scans

1. **Caches** — macOS: `~/Library/Caches/`, Linux: `~/.cache/`
2. **App leftovers** — Compare Application Support with installed apps
3. **Security** — SSH permissions, sensitive files, world-readable configs
4. **Hidden files** — Large hidden files/dirs in home
5. **Project artifacts** — `__pycache__`, `node_modules`, `dist`, `build`
6. **ML caches** — Hugging Face, PyTorch, TensorFlow (unused models >30 days)
7. **Dependencies** — Conflicts, unused, outdated via `uv pip check`

## Report Formats

**Markdown:** Summary, ML caches, dependencies, caches, security, cleanup recommendations.

**JSON:** Structured data for automation.

## Security

- No automatic deletions; analysis and recommendations only
- Fail-fast on config errors
- Path validation, structured logging

## Contributing

1. Fork, create branch, make changes
2. Run `uv run ruff check .`, `uv run pyright`, `uv run pytest`
3. Open Pull Request

## License

MIT. See [LICENSE](LICENSE).

## Author

Aleksandr Mordvinov — [GitHub](https://github.com/FUYOH666) | [scanovich.ai](https://scanovich.ai)
