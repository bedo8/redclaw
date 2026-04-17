"""Campaign orchestration engine — runs attack campaigns end-to-end."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from loguru import logger

from redclaw.adapters.base import AgentAdapter
from redclaw.adapters.http_agent import HttpAgentAdapter
from redclaw.attacks.base import AttackResult
from redclaw.config import AdapterType, CampaignConfig, CampaignPhase, TargetConfig
from redclaw.core.scheduler import PhaseResult, get_module


@dataclass
class CampaignResult:
    """Complete results from a campaign run."""

    campaign_name: str
    target_url: str
    adapter_type: str
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    phase_results: list[PhaseResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def all_results(self) -> list[AttackResult]:
        """Flatten all attack results across phases."""
        return [r for phase in self.phase_results for r in phase.attack_results]

    @property
    def total_attacks(self) -> int:
        return len(self.all_results)

    @property
    def successful_attacks(self) -> int:
        return sum(1 for r in self.all_results if r.succeeded)

    @property
    def defended_attacks(self) -> int:
        from redclaw.attacks.base import AttackStatus
        return sum(1 for r in self.all_results if r.status == AttackStatus.DEFENDED)

    @property
    def duration_seconds(self) -> float:
        if self.completed_at is None:
            return 0.0
        return (self.completed_at - self.started_at).total_seconds()


class CampaignEngine:
    """Orchestrates adversarial attack campaigns against target agents.

    Usage:
        engine = CampaignEngine(target_config, campaign_config)
        result = await engine.run()
    """

    def __init__(
        self,
        target: TargetConfig,
        campaign: CampaignConfig,
    ) -> None:
        self._target = target
        self._campaign = campaign
        self._adapter: AgentAdapter | None = None

    async def run(self) -> CampaignResult:
        """Execute the full campaign and return results."""
        result = CampaignResult(
            campaign_name=self._campaign.name,
            target_url=self._target.url,
            adapter_type=self._target.adapter.value,
        )

        adapter = self._create_adapter()

        logger.info(f"Starting campaign: {self._campaign.name}")
        logger.info(f"Target: {self._target.url} ({self._target.adapter.value})")
        logger.info(f"Phases: {len(self._campaign.phases)}")

        try:
            async with adapter:
                for i, phase in enumerate(self._campaign.phases):
                    logger.info(f"Phase {i + 1}/{len(self._campaign.phases)}: {phase.name}")
                    phase_result = await self._run_phase(phase, adapter)
                    result.phase_results.append(phase_result)

                    # Check total attack limit
                    if result.total_attacks >= self._campaign.max_total_attacks:
                        logger.warning(
                            f"Reached max attack limit ({self._campaign.max_total_attacks}). "
                            f"Stopping campaign."
                        )
                        break

        except Exception as exc:
            logger.error(f"Campaign failed: {exc}")
            result.metadata["error"] = str(exc)

        result.completed_at = datetime.now(UTC)

        logger.info(
            f"Campaign complete: {result.total_attacks} attacks, "
            f"{result.successful_attacks} succeeded, "
            f"{result.defended_attacks} defended, "
            f"{result.duration_seconds:.1f}s"
        )

        return result

    async def _run_phase(self, phase: CampaignPhase, adapter: AgentAdapter) -> PhaseResult:
        """Run a single campaign phase."""
        phase_result = PhaseResult(phase_name=phase.name)

        for module_id in phase.attack_modules:
            try:
                module = get_module(
                    module_id,
                    enable_mutations=self._campaign.payload_mutations,
                )
                # Set cooperative timeout — module checks this in its loop
                module._timeout_seconds = phase.timeout_seconds
                logger.info(f"  Running module: {module.name} ({module_id})")

                results = await module.execute(adapter, self._target)

                phase_result.attack_results.extend(results)
                phase_result.modules_run.append(module_id)

                succeeded = sum(1 for r in results if r.succeeded)
                logger.info(
                    f"  Module complete: {len(results)} attacks, "
                    f"{succeeded} succeeded"
                )

            except KeyError as exc:
                logger.error(f"  Module not found: {exc}")

        return phase_result

    def _create_adapter(self) -> AgentAdapter:
        """Create the appropriate adapter for the target."""
        if self._target.adapter == AdapterType.HTTP:
            return HttpAgentAdapter(self._target)
        if self._target.adapter == AdapterType.OPENCLAW:
            from redclaw.adapters.openclaw import OpenClawAdapter
            return OpenClawAdapter(self._target)
        if self._target.adapter == AdapterType.MCP:
            from redclaw.adapters.mcp import MCPAdapter
            return MCPAdapter(self._target)
        if self._target.adapter == AdapterType.CLAUDE_API:
            from redclaw.adapters.claude_api import ClaudeAPIAdapter
            return ClaudeAPIAdapter(self._target)
        raise ValueError(f"Unsupported adapter type: {self._target.adapter}")


def load_campaign_from_yaml(path: str | Path) -> CampaignConfig:
    """Load a campaign definition from a YAML file."""
    path = Path(path)
    with path.open() as f:
        data = yaml.safe_load(f)

    phases = [
        CampaignPhase(
            name=p["name"],
            attack_modules=p["attack_modules"],
            timeout_seconds=p.get("timeout_seconds", 300),
            max_concurrent=p.get("max_concurrent", 5),
        )
        for p in data.get("phases", [])
    ]

    return CampaignConfig(
        name=data["name"],
        description=data.get("description", ""),
        version=data.get("version", "1.0"),
        target_adapter=AdapterType(data.get("target_adapter", "http")),
        phases=phases,
        payload_mutations=data.get("payload_mutations", True),
        max_total_attacks=data.get("max_total_attacks", 200),
    )
