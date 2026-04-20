# Changelog

All notable changes to RedClaw are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Top-level public API: `redclaw.run_campaign`, `Target`, `Campaign`,
  `AdapterType`, `register_adapter`, `get_adapter`, `list_adapters`.
- `@register_adapter(identifier)` decorator — third-party adapters can now
  register themselves without touching `CampaignEngine`.
- `docs/extending.md` — how to add adapters, attack modules, and AATCK classes.
- Test coverage for the reporting layer, the Typer CLI, and HTTP adapter
  response parsing (via `httpx.MockTransport`).
- CI: `.github/workflows/test.yml` (matrix: ubuntu + macos × py 3.11/3.12/3.13)
  and `.github/workflows/build.yml` (tag-triggered sdist + wheel, attached to
  the matching GitHub Release; no PyPI upload).
- Pre-commit hooks (ruff, ruff-format, mypy, detect-secrets).
- Coverage regression gate via `pytest --cov-fail-under`.

### Changed
- Adapter instantiation moved from an `if/elif` chain in
  `CampaignEngine._create_adapter` to a registry lookup.
- Package version is now sourced from git tags via setuptools-scm
  (`pyproject.toml` declares `dynamic = ["version"]`).
- Minimum safe dependency bumps to clear reported CVEs (direct deps only).

### Fixed
- Clean mypy baseline (`strict_optional`, `warn_unused_ignores`,
  `warn_redundant_casts` — 0 errors).
- Ruff auto-fixes and format applied across the codebase.

## [0.2.0] — 2026-04-05

### Added
- AATCK v1.1: 8 attack classes covering 47 techniques.
- OpenClaw adapter for live testing against hardened agents.
- Observer improvements and structured campaign phases.

## [0.1.0] — 2026-03-24

### Added
- Initial framework: core engine, HTTP + Claude API + MCP adapters,
  prompt injection + tool abuse modules, HTML + JSON reporting.
- MIT license and project README.

[Unreleased]: https://github.com/bedo8/redclaw/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/bedo8/redclaw/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bedo8/redclaw/releases/tag/v0.1.0
