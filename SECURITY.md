# Security Policy

## Scope

RedClaw is an adversarial testing framework maintained internally by the
the project maintainer. This policy covers the RedClaw codebase itself —
not the target agents it probes.

## Supported versions

| Version  | Supported |
|----------|-----------|
| `main`   | ✅        |
| `0.2.x`  | ✅        |
| `< 0.2`  | ❌        |

Only the latest minor receives security patches. Older tags are kept for
reproducibility but will not be back-ported.

## Reporting a vulnerability

Report internally — **do not** open a public GitHub issue.

- **Primary contact:** Bedrettin (Bedo) Cakmak — `88455041+bedo8@users.noreply.github.com`
- **Team:** Maintainer

Include:
1. Affected version / commit SHA.
2. Reproduction steps or a proof-of-concept.
3. Impact assessment (what an attacker can do).
4. Any suggested remediation.

Expect an acknowledgement within **2 business days** and a fix or mitigation
plan within **10 business days** for high-severity issues.

## Dependency CVEs

Direct dependencies are monitored via Dependabot
([`.github/dependabot.yml`](.github/dependabot.yml)) and
[pip-audit](https://pypi.org/project/pip-audit/) in CI. The maintenance policy
for reported CVEs is **minimum-bump only** — upgrade to the lowest version
that clears the finding, to keep the patch surface small.

## Out of scope

- Attacks against target agents during normal RedClaw use — that's the
  intended function of this framework.
- Issues in optional extras (`openclaw`, `dashboard`) that only affect
  non-default installs are triaged at lower priority than core findings.
