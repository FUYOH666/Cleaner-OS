# Migration from clean-m1 / cleanmac scripts

If you used local [clean-m1](https://github.com/FUYOH666/Cleaner-OS) shell scripts (`cleanmac.sh`, `remove_orphaned_app_support.sh`), migrate to System Cleaner v1.0:

## Equivalent commands

| Old (shell) | New (syscleaner) |
|-------------|------------------|
| `./cleanmac.sh -d` | `syscleaner scan --all` then `syscleaner apply --from-scan results.json --dry-run` |
| `./cleanmac.sh -y` | `syscleaner apply --from-scan results.json --tier moderate --execute --yes` |
| `./remove_orphaned_app_support.sh -d` | `syscleaner scan --all` (orphaned App Support in findings) |
| Weekly launchd | `examples/com.syscleaner.weekly.plist` (scan + report only, no auto-delete) |

## What moved into recognizers

- Xcode DerivedData / Archives → `xcode_derived`, `xcode_archives`
- npm / Homebrew / pip caches → `npm_cache`, `homebrew_cache`, `pip_cache`
- Orphaned Application Support → `orphaned_app_support`
- uv / Cursor / Hugging Face / Ollama / Playwright → dedicated recognizers

## Safety difference

Shell scripts delete immediately after confirmation. System Cleaner defaults to **audit + dry-run apply** and prefers native tools (`uv cache prune`, `hf cache prune`, `brew cleanup -s`).
