# System Cleaner (syscleaner)

**Trusted audit and tiered cleanup for developer workstations — macOS and Linux.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/FUYOH666/Cleaner-OS/actions/workflows/ci.yml/badge.svg)](https://github.com/FUYOH666/Cleaner-OS/actions/workflows/ci.yml)

One scan surfaces caches, AI-era IDE junk, ML models, dependency issues, and security risks. You get structured reports and an optional **safe apply** path that prefers official tools (`uv`, `hf`, `brew`) over blind `rm`.

---

## Why this exists

| Pain | What syscleaner does |
|------|----------------------|
| Disk full of opaque caches | Recognizers for uv, Cursor, HF, Ollama, Xcode, npm, … |
| Unsure what is safe to delete | Risk tiers: `safe` / `moderate` / `risky` + dry-run by default |
| Secrets and SSH misconfigurations | Security audit + SARIF export for CI |
| ML models eating tens of GB | HF / PyTorch / TensorFlow cache analysis |
| Broken Python deps | `uv pip check` across discovered projects |

**Compared to generic cleaners** ([CleanMyMac](https://macpaw.com/cleanmymac), OnyX): dev-specific paths and audit-first workflow.

**Compared to dev-only tools** ([devpurge](https://github.com/sogadaiki/devpurge), [diskard](https://github.com/connectwithprakash/diskard)): adds **security + dependency + ML** analysis and SARIF, not only disk reclaim.

---

## Quick start

```bash
git clone https://github.com/FUYOH666/Cleaner-OS.git
cd Cleaner-OS
uv sync
uv run syscleaner scan --all --save-results scan.json
uv run syscleaner plan --from-scan scan.json
uv run syscleaner apply --from-scan scan.json --dry-run
```

Install as a tool:

```bash
uv tool install git+https://github.com/FUYOH666/Cleaner-OS.git
syscleaner health
```

---

## Commands

```bash
# Scan
syscleaner scan --all
syscleaner scan --caches --security --ml-cache --dependencies --projects

# Reports
syscleaner scan --all --save-results scan.json
syscleaner report -f markdown -o report.md --from-scan scan.json
syscleaner export-sarif --from-scan scan.json -o results.sarif

# Cleanup (dry-run default)
syscleaner plan --from-scan scan.json
syscleaner plan --from-scan scan.json --target-gb 20
syscleaner apply --from-scan scan.json --dry-run
syscleaner apply --from-scan scan.json --tier safe --execute --yes

# Health / schema
syscleaner health
syscleaner healthz
syscleaner export-schema -o scan-bundle.schema.json

# Profiles (in config.yaml): default | ml-workstation | ios-dev | minimal
```

Aliases: `system-cleaner`

---

## Safety model

1. **Scan** never deletes.
2. **`apply`** defaults to **dry-run**.
3. **`--tier safe`** limits to low-risk actions (e.g. `uv cache prune`).
4. **`--allow-risky`** required for `node_modules` and similar.
5. Missing CLI binaries → logged as manual steps, not silent failure.

See [docs/PRODUCT.md](docs/PRODUCT.md).

---

## Configuration

```bash
cp config.yaml.example config.yaml
```

Enable/disable recognizers, excludes, and security patterns in YAML. See [config.yaml.example](config.yaml.example).

---

## Automation

- Weekly **scan + report** (no auto-delete): [examples/com.syscleaner.weekly.plist](examples/com.syscleaner.weekly.plist)
- CI security: `syscleaner export-sarif` → upload to GitHub Code Scanning
- Migrating from shell scripts: [docs/migration-from-cleanmac.md](docs/migration-from-cleanmac.md)

---

## Also see (ecosystem)

- [devpurge](https://github.com/sogadaiki/devpurge) — macOS dev cache purge
- [diskard](https://github.com/connectwithprakash/diskard) — recognizer-based cleanup
- [mac-cleanup](https://github.com/Yurzs/mac-cleanup) — interactive macOS cleanup

---

## Contributing

1. Fork and branch
2. `uv sync --all-groups && uv run ruff check . && uv run pytest`
3. Open a PR

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Professional support

Optional deployment and customization: [docs/COMMERCIAL.md](docs/COMMERCIAL.md).

## License

MIT — see [LICENSE](LICENSE).

## Author

[Aleksandr Mordvinov](https://github.com/FUYOH666) · [scanovich.ai](https://scanovich.ai)
