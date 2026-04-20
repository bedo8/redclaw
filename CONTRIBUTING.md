# Contributing to RedClaw

Short reference for the GRC-W Team and internal collaborators.

## Dev setup

```bash
git clone https://github.com/bedo8/redclaw.git
cd redclaw
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,openclaw]"
pre-commit install
```

## Quality gates (must pass locally before opening a PR)

```bash
ruff check redclaw/ tests/
ruff format --check redclaw/ tests/
mypy redclaw/
pytest   # enforces --cov-fail-under=45
```

The CI matrix (`.github/workflows/test.yml`) runs the same commands on
ubuntu + macos × py 3.11 / 3.12 / 3.13. Red CI blocks merge.

## Commit style

Conventional-Commits-ish prefixes, already used throughout history:

- `feat:` — new user-visible behavior
- `fix:` — bug fix
- `refactor:` — internal restructure, no behavior change
- `test:` — tests only
- `docs:` — docs only
- `build:` / `ci:` — packaging or workflow changes
- `security:` — dependency bumps to clear a CVE
- `chore:` / `style:` — mechanical housekeeping

Scope (the `(area)` in `feat(area): ...`) is optional — use it when the
change is confined to one subsystem (e.g. `feat(api):`, `refactor(adapters):`).

## Extension points

If you're adding a new adapter, attack module, or AATCK class, follow
[docs/extending.md](docs/extending.md) — no engine or CLI edits should be
needed.

## PR checklist

- [ ] Tests added or updated (coverage gate is 45%).
- [ ] `pre-commit run --all-files` is clean.
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if the change is user-visible.
- [ ] Relevant docs updated (README, `docs/extending.md`, `docs/AATCK_FRAMEWORK.md`).

## Releases

Releases are tag-driven. Do not hand-edit version numbers.

```bash
git tag -a v0.3.0 -m "v0.3.0"
git push origin v0.3.0
```

That triggers `.github/workflows/build.yml`, which builds sdist + wheel with
setuptools-scm, runs `twine check`, and attaches the artifacts to the
auto-created GitHub Release. Install is `pip install` from the release URL or
`pip install git+https://github.com/bedo8/redclaw.git@v0.3.0`. No PyPI upload.

Before tagging, promote the `[Unreleased]` section of `CHANGELOG.md` to a
dated release heading.
