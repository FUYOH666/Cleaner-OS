# Optional helper scripts

These are **optional** shell examples. Core functionality lives in the `syscleaner` CLI.

Prefer:

```bash
syscleaner scan --all
syscleaner health
```

## Included examples

| File | Purpose |
|------|---------|
| `system_health_check.sh.example` | GPU, CPU, memory, disk, Docker (macOS/Linux) |
| `backup_configs.sh.example` | Backup SSH, shell, and `config.yaml` |

## Usage

```bash
cp scripts/system_health_check.sh.example scripts/system_health_check.sh
chmod +x scripts/system_health_check.sh
./scripts/system_health_check.sh
```

Copy `.example` files before editing. Do not commit personalized copies with secrets or host-specific paths.
