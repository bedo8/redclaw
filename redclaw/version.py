"""Single source of truth for the installed RedClaw version.

The version comes from package metadata (written by setuptools-scm at build
or editable-install time), so nothing in the codebase hardcodes it.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("redclaw")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
