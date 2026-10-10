"""Secret redaction for evidence that is written to disk or shown on screen.

Targets under test sometimes leak real credentials. Reports must prove the
leak happened without becoming a second copy of the credential, so evidence
is passed through :func:`redact` before it is stored. RedClaw's own canary
tokens are never redacted; they are the proof.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

_CANARY = re.compile(r"^REDCLAW_\w*CANARY\w*$")

# (label, pattern). Order matters: specific formats before generic ones.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"
        ),
    ),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
    ("api_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    ),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*")),
]

# key = value / key: value assignments for secret-looking keys.
_ASSIGNMENT = re.compile(
    r"(?i)\b((?:[a-z0-9_]*?)(?:api[_-]?key|secret|token|passw(?:or)?d|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)[a-z0-9_-]*[\"']?\s*[:=]\s*)([\"']?)([^\s\"',;}]{6,})"
)


def _assignment_sub(match: re.Match[str]) -> str:
    prefix, quote, value = match.groups()
    if _CANARY.match(value) or value.startswith("[REDACTED"):
        return match.group(0)
    return f"{prefix}{quote}[REDACTED]"


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Replace credential-shaped substrings in ``text`` with ``[REDACTED:<kind>]``.

    Args:
        text: Free text (agent response, evidence string, URL...).
        secrets: Exact values to scrub as well, such as the token RedClaw
            itself used to authenticate to the target.
    """
    if not text:
        return text
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "[REDACTED:configured_secret]")
    for label, pattern in _PATTERNS:
        text = pattern.sub(f"[REDACTED:{label}]", text)
    return _ASSIGNMENT.sub(_assignment_sub, text)


__all__ = ["redact"]
