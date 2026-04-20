"""RedClaw adapter package.

Importing this package registers all built-in adapters. External code that
adds adapters via `@register_adapter(...)` must import its module at least
once for the registration side-effect to run.
"""

from __future__ import annotations

import contextlib

# Import built-in adapters so their @register_adapter decorators fire.
# Optional-dep adapters (openclaw, claude_api) guard their imports so a
# missing extra (e.g. `websockets` for openclaw) doesn't break the package.
from redclaw.adapters import (
    http_agent,  # noqa: F401
    mcp,  # noqa: F401
)
from redclaw.adapters.base import (
    AgentAdapter,
    AgentResponse,
    get_adapter,
    list_adapters,
    register_adapter,
)

with contextlib.suppress(ImportError):
    from redclaw.adapters import openclaw  # noqa: F401

with contextlib.suppress(ImportError):
    from redclaw.adapters import claude_api  # noqa: F401


__all__ = [
    "AgentAdapter",
    "AgentResponse",
    "get_adapter",
    "list_adapters",
    "register_adapter",
]
