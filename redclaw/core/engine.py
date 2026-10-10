"""Campaign orchestration engine — runs attack campaigns end-to-end."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

import redclaw.adapters  # noqa: F401 — triggers adapter registrations
from redclaw.adapters.base import AgentAdapter, get_adapter
from redclaw.attacks.base import DEFAULT_CANARY_URL, AttackResult, AttackStatus, Severity
from redclaw.config import CampaignConfig, CampaignPhase, RedClawSettings, TargetConfig
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
        return sum(1 for r in self.all_results if r.status == AttackStatus.DEFENDED)

    @property
    def duration_seconds(self) -> float:
        if self.completed_at is None:
            return 0.0
        return (self.completed_at - self.started_at).total_seconds()


class CampaignEngine:
    """Orchestrates adversarial attack campaigns against target agents.

    * Attacks within a module run concurrently up to the phase's
      ``max_concurrent`` (when the adapter supports it), each in an isolated
      adapter session.
    * ``max_total_attacks`` caps the number of attempts across the campaign.
    * When enabled, a loopback canary server runs for the whole campaign.
      Payloads point exfiltration URLs at it, and any request that carries an
      attack's canary marks that attack as successful (out-of-band
      detection), even if the agent's reply looked clean.

    Usage::

        engine = CampaignEngine(target_config, campaign_config)
        result = await engine.run()
    """

    def __init__(
        self,
        target: TargetConfig,
        campaign: CampaignConfig,
        settings: RedClawSettings | None = None,
    ) -> None:
        self._target = target
        self._campaign = campaign
        self._settings = settings or RedClawSettings()
        self._canary_url = DEFAULT_CANARY_URL

    async def run(self) -> CampaignResult:
        """Execute the full campaign and return results."""
        result = CampaignResult(
            campaign_name=self._campaign.name,
            target_url=self._target.url,
            adapter_type=self._target.adapter.value,
        )
        logger.info(f"Starting campaign: {self._campaign.name}")
        logger.info(f"Target: {self._target.url} ({self._target.adapter.value})")

        async with contextlib.AsyncExitStack() as stack:
            canary = await self._start_canary(stack, result)
            try:
                adapter = self._create_adapter()
                await stack.enter_async_context(adapter)
                await self._run_phases(adapter, result)
            except Exception as exc:
                logger.error(f"Campaign failed: {exc}")
                result.metadata["error"] = str(exc)

            if canary is not None:
                await asyncio.sleep(self._settings.canary_grace_seconds)
                self._apply_out_of_band(canary, result)

        result.completed_at = datetime.now(UTC)
        logger.info(
            f"Campaign complete: {result.total_attacks} attacks, "
            f"{result.successful_attacks} succeeded, {result.defended_attacks} defended, "
            f"{result.duration_seconds:.1f}s"
        )
        return result

    # ------------------------------------------------------------------
    async def _start_canary(
        self, stack: contextlib.AsyncExitStack, result: CampaignResult
    ) -> Any | None:
        if not self._settings.canary_enabled:
            return None
        from redclaw.mock_services.canary_server import CanaryServer

        server = CanaryServer(host=self._settings.canary_host, port=self._settings.canary_port)
        try:
            await stack.enter_async_context(server)
        except OSError as exc:
            logger.warning(f"Canary server unavailable ({exc}); out-of-band detection disabled")
            result.metadata["canary_server"] = f"unavailable: {exc}"
            return None
        self._canary_url = server.url
        result.metadata["canary_server"] = server.url
        return server

    def _apply_out_of_band(self, canary: Any, result: CampaignResult) -> None:
        """Upgrade attacks whose canary reached the canary server to SUCCESS."""
        hits = 0
        for r in result.all_results:
            if not r.canary_token:
                continue
            requests = canary.check_canary(r.canary_token)
            if not requests:
                continue
            hits += 1
            r.metadata["out_of_band"] = [
                {"method": q.method, "path": q.path, "at": q.timestamp.isoformat()}
                for q in requests[:5]
            ]
            r.canary_detected = True
            if r.status != AttackStatus.SUCCESS:
                r.status = AttackStatus.SUCCESS
                r.confidence = 0.95
                r.severity = max(r.severity, Severity.HIGH, key=_severity_rank)
                r.evidence = (
                    f"Out-of-band: target sent {len(requests)} request(s) carrying the canary to "
                    f"{canary.url}{requests[0].path}. | {r.evidence}"
                )
        result.metadata["out_of_band_hits"] = hits
        if hits:
            logger.warning(f"{hits} attack(s) confirmed by out-of-band canary requests")

    # ------------------------------------------------------------------
    async def _run_phases(self, adapter: AgentAdapter, result: CampaignResult) -> None:
        remaining = self._campaign.max_total_attacks
        for i, phase in enumerate(self._campaign.phases):
            if remaining <= 0:
                logger.warning(
                    f"Reached max_total_attacks ({self._campaign.max_total_attacks}); "
                    "stopping campaign."
                )
                result.metadata["truncated"] = True
                break
            logger.info(f"Phase {i + 1}/{len(self._campaign.phases)}: {phase.name}")
            phase_result = await self._run_phase(phase, adapter, remaining)
            result.phase_results.append(phase_result)
            remaining -= phase_result.total_attacks

    async def _run_phase(
        self, phase: CampaignPhase, adapter: AgentAdapter, budget: int
    ) -> PhaseResult:
        """Run a single campaign phase within the remaining attack budget."""
        phase_result = PhaseResult(phase_name=phase.name)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + phase.timeout_seconds

        for module_id in phase.attack_modules:
            remaining_budget = budget - phase_result.total_attacks
            remaining_time = deadline - loop.time()
            if remaining_budget <= 0 or remaining_time <= 0:
                break
            module = get_module(module_id, enable_mutations=self._campaign.payload_mutations)
            module.configure(
                timeout_seconds=remaining_time,
                max_concurrent=phase.max_concurrent,
                max_attempts=remaining_budget,
                canary_url=self._canary_url,
            )
            logger.info(f"  Running module: {module.name} ({module_id})")
            results = await module.execute(adapter, self._target)
            phase_result.attack_results.extend(results)
            phase_result.modules_run.append(module_id)

        return phase_result

    def _create_adapter(self) -> AgentAdapter:
        """Create the appropriate adapter for the target via the registry."""
        try:
            return get_adapter(self._target.adapter.value, self._target, settings=self._settings)
        except KeyError as exc:
            raise ValueError(f"Unsupported adapter type: {self._target.adapter}") from exc


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _severity_rank(severity: Severity) -> int:
    return _SEVERITY_ORDER.index(severity)


def load_campaign_from_yaml(path: str | Path) -> CampaignConfig:
    """Load a campaign definition from a YAML file (kept for API compatibility)."""
    from redclaw.campaigns import load_campaign_file

    return load_campaign_file(path)
