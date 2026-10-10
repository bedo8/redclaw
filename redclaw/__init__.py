"""RedClaw — Adversarial AI Agent Red Team Framework.

Public API (stable across minor versions)::

    from redclaw import run_campaign, Target, Campaign, AdapterType

    result = await run_campaign(
        target=Target(url="http://127.0.0.1:8080", adapter=AdapterType.HTTP),
        campaign=Campaign(name="quick-scan", phases=[...]),
    )

Modules under :mod:`redclaw` (core, attacks, adapters, reporting, …) are
considered internal — their layout may change between minor versions. Use
the names re-exported here for long-lived integrations.
"""

from __future__ import annotations

from loguru import logger

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
from redclaw.version import __version__

# Library code stays quiet unless the caller opts in; the CLI does this via
# redclaw._logging.configure_logging().
logger.disable("redclaw")


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
