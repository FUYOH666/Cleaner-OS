# PyPI publish (deferred)

PyPI publish is **not** required to use Cleaner-OS today. Install from source:

```bash
git clone https://github.com/FUYOH666/Cleaner-OS.git
cd Cleaner-OS && uv sync
uv run syscleaner health
```

## When ready to publish

1. Create project **syscleaner** on https://pypi.org (name was free at v1.2.1 prep).
2. Add **trusted publisher**: GitHub `FUYOH666/Cleaner-OS`, workflow `publish.yml`, no environment.
   - Or set repository secret `PYPI_API_TOKEN`.
3. In `.github/workflows/publish.yml`, restore the `push: tags: ["v*"]` trigger (disabled during deferred publish to avoid failed release emails).
4. Run publish:

```bash
gh workflow run publish.yml --repo FUYOH666/Cleaner-OS -f tag=v1.2.1
```

5. Verify: `pip install syscleaner==1.2.1`
6. In [pyproject.toml](../pyproject.toml): set `Development Status :: 5 - Production/Stable`.
7. Upload [docs/assets/social-preview.png](assets/social-preview.png) in GitHub repo Settings.

See [GITHUB_SETUP.md](GITHUB_SETUP.md) for branch protection and release steps.
