# Contributing to RedClaw

## Dev setup

```bash
git clone https://github.com/bedo8/redclaw.git
cd redclaw
python -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements.lock   # pinned, hash-checked
pip install --no-deps -e .
pre-commit install                                   # optional: pip install pre-commit
```

## Checks (CI runs the same)

```bash
ruff check redclaw/ tests/
ruff format --check redclaw/ tests/
mypy redclaw/
pytest                       # coverage gate: 80%
pip-audit --require-hashes --disable-pip -r requirements.lock
```

The test suite starts loopback-only servers (the mock agent, a mock MCP
server, a fake Messages API) and never talks to external hosts.

`.github/workflows/test.yml` runs lint, types, pip-audit, the test matrix
(ubuntu and macOS, Python 3.11 to 3.14) and an end-to-end scan of the
bundled mock agent from a freshly built wheel.

## Dependencies

Ranges live in `pyproject.toml`; exact, hashed pins live in
`requirements.lock`. After changing a range (or merging a Dependabot bump),
regenerate the lock and audit it:

```bash
uv pip compile pyproject.toml --extra dashboard --extra openclaw --extra dev \
  --universal --python-version 3.11 --generate-hashes -o requirements.lock
pip-audit --require-hashes --disable-pip -r requirements.lock
```

## Commit style

Conventional-commit prefixes: `feat:`, `fix:`, `refactor:`, `test:`,
`docs:`, `build:`, `ci:`, `chore:`, `style:`. Add a scope when the change
is confined to one area, e.g. `fix(adapters):`.

## Extension points

New adapters, attack modules and AATCK classes plug into registries; see
[docs/extending.md](docs/extending.md). If you add or change an AATCK
technique, update its OWASP/ATLAS mappings in `redclaw/scoring/aatck.py`
and the tables in `docs/AATCK_FRAMEWORK.md` (a test checks they agree).

## Pull requests

- Tests added or updated.
- `pre-commit run --all-files` is clean.
- `CHANGELOG.md` updated under `[Unreleased]` for user-visible changes.
- Docs updated where relevant.

## Releases

Releases are tag-driven; the version comes from the git tag via
setuptools-scm, so never hand-edit it.

```bash
git tag -a v0.3.0 -m "v0.3.0"
git push origin v0.3.0
```

`.github/workflows/build.yml` builds the sdist and wheel, checks them, and
attaches them to the GitHub Release. Move the `[Unreleased]` section of
`CHANGELOG.md` under a dated heading before tagging.
