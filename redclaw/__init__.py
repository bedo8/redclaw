"""RedClaw — Adversarial AI Agent Red Team Framework.

Public API (stable across minor versions)::

    from redclaw import run_campaign, Target, Campaign, AdapterType

    result = await run_campaign(
        target=Target(url="http://localhost:8080", adapter=AdapterType.HTTP),
        campaign=Campaign(name="quick-scan", phases=[...]),
    )

Modules under :mod:`redclaw` (core, attacks, adapters, reporting, …) are
considered internal — their layout may change between minor versions. Use
the names re-exported here for long-lived integrations.
"""

from __future__ import annotations

from redclaw.adapters.base import (
    AgentAdapter,
    AgentResponse,
    get_adapter,
    list_adapters,
    register_adapter,
)
from redclaw.attacks.base import AttackResult, AttackStatus, Severity
from redclaw.config import (
    AdapterType,
    CampaignPhase,
    RedClawSettings,
)
from redclaw.config import (
    CampaignConfig as Campaign,
)
from redclaw.config import (
    TargetConfig as Target,
)
from redclaw.core.engine import CampaignEngine, CampaignResult

try:
    from redclaw._version import __version__
except ImportError:  # running from a source checkout without a build
    from importlib.metadata import PackageNotFoundError, version

    try:
        __version__ = version("redclaw")
    except PackageNotFoundError:
        __version__ = "0.0.0+unknown"


async def run_campaign(target: Target, campaign: Campaign) -> CampaignResult:
    """Run a campaign against a target agent and return the aggregated result.

    Convenience wrapper around :class:`CampaignEngine` for the common case
    where callers don't need to hold on to the engine instance.
    """
    engine = CampaignEngine(target=target, campaign=campaign)
    return await engine.run()


__all__ = [
    "AdapterType",
    "AgentAdapter",
    "AgentResponse",
    "AttackResult",
    "AttackStatus",
    "Campaign",
    "CampaignEngine",
    "CampaignPhase",
    "CampaignResult",
    "RedClawSettings",
    "Severity",
    "Target",
    "__version__",
    "get_adapter",
    "list_adapters",
    "register_adapter",
    "run_campaign",
]
