# Release Process

## Quick Release (Automated)

### Prerequisites (one-time setup)
1. Add PyPI token to GitHub secrets:
   - Go to: https://github.com/girste/mcp-cybersec-watchdog/settings/secrets/actions
   - Click "New repository secret"
   - Name: `PYPI_TOKEN`
   - Value: `pypi-AgEI...` (your PyPI token)

### Release Steps (every release)

```bash
# 1. Update version in pyproject.toml
vim pyproject.toml
# Change: version = "0.1.1"  (increment from 0.1.0)

# 2. Commit version bump
git add pyproject.toml
git commit -m "Bump version to 0.1.1"
git push origin main

# 3. Create GitHub Release (triggers auto-publish to PyPI)
gh release create v0.1.1 \
  --title "v0.1.1 - Bug fixes and improvements" \
  --notes "## Changes
- Fixed bug X
- Improved feature Y
- Updated dependencies"

# That's it! GitHub Actions will:
# ✓ Build the package
# ✓ Upload to PyPI
# ✓ Attach build artifacts to GitHub release
```

### Verify Release

```bash
# Wait ~2 minutes, then verify:
pip install --upgrade mcp-cybersec-watchdog
mcp-watchdog --version  # Should show 0.1.1
```

---

## Manual Release (if workflow fails)

```bash
# 1. Update version in pyproject.toml
vim pyproject.toml

# 2. Commit and tag
git add pyproject.toml
git commit -m "Bump version to 0.1.1"
git tag v0.1.1
git push origin main --tags

# 3. Build
rm -rf dist/ build/
venv/bin/python -m build

# 4. Upload to PyPI
TWINE_PASSWORD='your-pypi-token' venv/bin/twine upload dist/*

# 5. Create GitHub Release
gh release create v0.1.1 --title "v0.1.1" dist/*
```

---

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **0.1.0 → 0.1.1**: Bug fixes (patch)
- **0.1.0 → 0.2.0**: New features (minor)
- **0.9.0 → 1.0.0**: Breaking changes (major)

---

## Checklist Before Release

- [ ] All tests pass (`pytest tests/`)
- [ ] Code formatted (`black src/ tests/`)
- [ ] Linting clean (`ruff check src/ tests/`)
- [ ] Updated CHANGELOG or release notes
- [ ] Version bumped in `pyproject.toml`
- [ ] Committed and tagged

---

## Troubleshooting

**"File already exists"**: You can't upload the same version twice. Bump version number.

**"Invalid token"**: Check `PYPI_TOKEN` secret in GitHub settings.

**"Workflow didn't run"**: GitHub Release must be "published", not "draft".
