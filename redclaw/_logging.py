"""Logging setup.

RedClaw logs through loguru. The library is silent by default
(``logger.disable("redclaw")`` in the package ``__init__``) so importing it
never spams the host application's stderr; the CLI calls
:func:`configure_logging` to turn output on at the requested level.
"""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger


def configure_logging(level: str = "WARNING", log_file: Path | None = None) -> None:
    """Route RedClaw logs to stderr (and optionally a file) at ``level``."""
    logger.remove()
    logger.enable("redclaw")
    logger.add(sys.stderr, level=level.upper(), format="<level>{level: <8}</level> {message}")
    if log_file is not None:
        logger.add(log_file, level="DEBUG", rotation="10 MB", retention=3)
