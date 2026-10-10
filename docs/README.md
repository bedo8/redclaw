# RedClaw documentation

Start with the project [README](../README.md) for install and usage. This
directory holds the reference and background material.

| Document | What it is |
|----------|------------|
| [AATCK_FRAMEWORK.md](AATCK_FRAMEWORK.md) | The full AATCK taxonomy — 8 attack classes, 47 techniques, with detection and remediation guidance and the per-technique OWASP LLM Top 10 (2025) and MITRE ATLAS mappings. The canonical reference the scoring engine and reports are built on. |
| [extending.md](extending.md) | How to add adapters, attack modules and AATCK classes through the registries, without editing the engine or CLI. |
| [AATCK_Explainer.html](AATCK_Explainer.html) | A self-contained visual explainer of the taxonomy for sharing or presenting. Open it in a browser. |
| [Medium_Article.md](Medium_Article.md) | The author's background article introducing AATCK as a MITRE ATT&CK-style framework for AI agent security. |

The OWASP and MITRE ATLAS mappings live in code at
[`redclaw/scoring/aatck.py`](../redclaw/scoring/aatck.py); the framework
document and the reports are rendered from the same data.
