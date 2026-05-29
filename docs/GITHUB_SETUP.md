# GitHub repository setup (maintainer)

## Branch protection (`main`)

```bash
gh api repos/FUYOH666/Cleaner-OS/branches/main/protection -X PUT \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["test"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

If the required check name differs, list contexts with:

```bash
gh api repos/FUYOH666/Cleaner-OS/commits/main/check-runs --jq '.check_runs[].name'
```

## PyPI trusted publishing

1. Create project `syscleaner` on PyPI (name is free as of v1.1.0 prep).
2. **Publishing → Trusted publishers → Add**: GitHub, owner `FUYOH666`, repo `Cleaner-OS`, workflow `publish.yml`, environment blank.
3. Re-run failed publish or push a new tag:

```bash
gh workflow run publish.yml --ref v1.1.0
# or: git tag -f v1.1.0 && git push -f origin v1.1.0  (only if no successful publish yet)
```

Claims from a failed run are listed in the Actions log (`repository`, `workflow_ref`, `ref`).

## Social preview

Committed: [docs/assets/social-preview.png](assets/social-preview.png). Upload in **Settings → General → Social preview** if GitHub does not pick it from the default Open Graph path.

## Release

```bash
git tag -a v1.1.0 -m "v1.1.0: i18n, TUI, MCP, PyPI"
git push origin v1.1.0
gh release create v1.1.0 --notes-file CHANGELOG.md
```

## Dependencies

Dependabot is disabled. Update via `uv lock --upgrade-package <name>`.
