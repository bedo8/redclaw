# Changelog

All notable changes to RedClaw are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- HTML reports are rendered with Jinja2 autoescaping; the dashboard escapes
  every interpolated value (including `'`), uses no inline handlers, sends a
  strict CSP, and confines report lookups with `resolve().is_relative_to()`.
- Evidence and payloads are redacted for common credential formats before
  they are written; report files are created `0600`.
- `auth_token`, `auth_header` and the Anthropic API key are `SecretStr`.
- CI: least-privilege `permissions:`, actions pinned to commit SHAs,
  `contents: write` only in the release job, pip-audit on a hashed lock.

### Fixed
- Errored attacks no longer count as failed defenses: an unreachable target
  is reported as inconclusive (exit code 2), not as F 0/100.
- Campaign YAMLs ship in the wheel and are loaded with `importlib.resources`;
  unknown campaign names are an error instead of silently running a
  prompt-injection-only scan.
- MCP adapter: `shlex.split` for the server command, stderr drained, and a
  real Streamable HTTP transport via the official `mcp` SDK (the previous
  "SSE" mode did not speak MCP).
- HTTP adapter: no `IndexError` on `{"choices": []}`, 405 treated like 404
  during endpoint discovery, OpenAI-format bodies for
  `/v1/chat/completions`, custom endpoint paths posted verbatim.
- Claude API adapter uses `ANTHROPIC_API_KEY`/`ANTHROPIC_BASE_URL` and works
  with anthropic 1.x.
- `redclaw report --format` is honoured.
- Version comes from package metadata instead of a hardcoded `0.1.0`;
  default log level is `WARNING`.

### Added
- SARIF 2.1.0 and JUnit XML output (`--format sarif,junit` or `all`).
- OWASP Top 10 for LLM Applications 2025 and MITRE ATLAS mappings for every
  AATCK technique, shown in all report formats and in
  `docs/AATCK_FRAMEWORK.md`.
- Concurrent attack execution bounded by each phase's `max_concurrent`;
  `max_total_attacks` and phase timeouts are enforced.
- Out-of-band exfiltration detection: the loopback canary server runs
  during scans and confirms attacks whose canary reaches it.
- CLI: `--auth-token` (env `REDCLAW_AUTH_TOKEN`), `--insecure`, `--timeout`,
  `--model`, `--system-prompt`, `--mcp-tool`, `--no-canary`,
  `--fail-on-findings`, `--log-level`, `--version`.
- End-to-end CI job scanning the bundled mock agent and mock MCP server.
- Stdlib-only mock agent (no extras needed) and a mock MCP server CLI.

### Changed
- Dependencies use bounded ranges with a hash-pinned `requirements.lock`;
  `mcp` is a core dependency; `jinja2>=3.1.6`, `anthropic>=1,<2`.
- Attack modules share one execution path in `AttackModule`.
- Unused settings (`db_path`, `mutation_model`, report format/output dir,
  `declared_intent`) were removed.
- Background article and explainer moved to `docs/`.

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
