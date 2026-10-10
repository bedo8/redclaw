# Security Policy

## Scope

This policy covers the RedClaw codebase itself: the CLI, the scanning engine,
the adapters, the report generators, the dashboard and the bundled mock
services. It does not cover the target agents you point RedClaw at.

## Supported versions

| Version | Supported |
|---------|-----------|
| `main`  | Yes       |
| `0.3.x` | Yes       |
| `< 0.3` | No        |

Only the latest minor release receives security fixes.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Report it privately to the maintainer, **Bedrettin Cakmak** ([@bedo8](https://github.com/bedo8)),
through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on
[github.com/bedo8/redclaw](https://github.com/bedo8/redclaw/security/advisories/new).

Include:

1. The affected version or commit SHA.
2. Steps to reproduce or a proof of concept.
3. The impact (what an attacker can do).
4. A suggested fix, if you have one.

You should get an acknowledgement within a few days. High-severity issues get
a fix or a documented mitigation as quickly as practical.

## Handling of scan data

Scan reports contain the target's responses, which can include secrets the
target leaked. RedClaw redacts common credential formats before writing
evidence to disk and creates report files with `0600` permissions, but treat
the `reports/` directory as sensitive and do not commit it.

## Dependencies

Dependencies are bounded in `pyproject.toml` and pinned in
`requirements.lock`. CI runs [pip-audit](https://pypi.org/project/pip-audit/)
against the lock file on every push, and Dependabot proposes updates weekly.

## Out of scope

- Using RedClaw against agents you are not authorized to test. That is a
  misuse of the tool, not a vulnerability in it.
- The bundled mock agent and mock MCP server are intentionally vulnerable
  and bind to loopback only. Findings in them are expected behavior.
