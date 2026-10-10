"""Base classes for all RedClaw attack modules."""

from __future__ import annotations

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar

from loguru import logger

if TYPE_CHECKING:
    from redclaw.adapters.base import AgentAdapter, AgentResponse
    from redclaw.config import TargetConfig
    from redclaw.core.observer import ObservationResult

DEFAULT_CANARY_URL = "http://127.0.0.1:8299"


class Severity(StrEnum):
    """Attack finding severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AttackStatus(StrEnum):
    """Result status of an individual attack attempt."""

    SUCCESS = "success"  # Attack succeeded — agent was compromised
    DEFENDED = "defended"  # Agent resisted the attack
    ERROR = "error"  # Attack couldn't execute (target error, timeout)
    PARTIAL = "partial"  # Some indicators of compromise, not definitive
    SKIPPED = "skipped"  # Attack was skipped (prerequisites not met)


@dataclass
class AttackResult:
    """Result of a single attack attempt against a target agent."""

    attack_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    module_name: str = ""
    aatck_id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    status: AttackStatus = AttackStatus.DEFENDED
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.0  # 0.0 – 1.0: how certain we are of the result
    payload_used: str = ""
    evidence: str = ""  # Agent response proving compromise
    canary_detected: bool = False  # Whether canary token appeared in response
    canary_token: str = ""  # The canary embedded in this attack's payload
    remediation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        """Whether this attack compromised the target."""
        return self.status == AttackStatus.SUCCESS


@dataclass
class Payload:
    """A single attack payload with metadata.

    Single-shot payloads use ``content``. Multi-turn attacks set ``turns``;
    ``content`` then holds the final turn for display purposes.
    """

    content: str
    technique_id: str
    canary_token: str = ""
    description: str = ""
    mutated: bool = False
    mutation_type: str = ""
    turns: list[str] | None = None

    @property
    def messages(self) -> list[str]:
        return list(self.turns) if self.turns else [self.content]

    @property
    def transcript(self) -> str:
        return "\n---\n".join(self.messages)


class AttackModule(ABC):
    """Abstract base class for all RedClaw attack modules.

    Subclasses provide ``name``, ``aatck_ids``, ``description`` and
    ``payloads()``. The default :meth:`execute` sends every payload through
    the adapter (concurrently when the adapter allows it), runs the observer
    on the response, and builds an :class:`AttackResult` using the
    per-technique ``SEVERITY`` and ``REMEDIATION`` tables. Override the
    ``*_evidence`` / ``*_confidence`` hooks to customise the result text.
    """

    SEVERITY: ClassVar[dict[str, Severity]] = {}
    REMEDIATION: ClassVar[dict[str, str]] = {}
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.MEDIUM
    DEFAULT_REMEDIATION: ClassVar[str] = "Review and strengthen input validation."
    DEFENDED_CONFIDENCE: ClassVar[float] = 0.85

    # Runtime knobs set by CampaignEngine via configure().
    _timeout_seconds: float | None = None
    _max_concurrent: int = 1
    _max_attempts: int | None = None
    _canary_url: str = DEFAULT_CANARY_URL

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable module name."""

    @property
    @abstractmethod
    def aatck_ids(self) -> list[str]:
        """AATCK class IDs this module covers (e.g. ['AATCK-001'])."""

    @property
    @abstractmethod
    def description(self) -> str:
        """What this attack module tests."""

    @abstractmethod
    def payloads(self) -> list[Payload]:
        """Generate all attack payloads for this module."""

    @property
    def aatck_id(self) -> str:
        """Primary AATCK class for results produced by this module."""
        return self.aatck_ids[0]

    def configure(
        self,
        *,
        timeout_seconds: float | None = None,
        max_concurrent: int = 1,
        max_attempts: int | None = None,
        canary_url: str | None = None,
    ) -> None:
        """Apply per-phase limits. Called by the engine before ``execute``."""
        self._timeout_seconds = timeout_seconds
        self._max_concurrent = max(1, max_concurrent)
        self._max_attempts = max_attempts
        if canary_url:
            self._canary_url = canary_url

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    async def execute(
        self,
        adapter: AgentAdapter,
        target_config: TargetConfig,
    ) -> list[AttackResult]:
        """Run the module's payloads against the target and return results."""
        payloads = self.payloads()
        if self._max_attempts is not None:
            payloads = payloads[: max(0, self._max_attempts)]

        concurrency = self._max_concurrent if adapter.supports_concurrency else 1
        semaphore = asyncio.Semaphore(concurrency)
        deadline = (
            time.monotonic() + self._timeout_seconds
            if self._timeout_seconds and self._timeout_seconds > 0
            else None
        )
        logger.info(
            f"{self.name}: {len(payloads)} payloads, concurrency {concurrency}"
            + (f", budget {self._timeout_seconds:.0f}s" if deadline else "")
        )

        async def run(payload: Payload) -> AttackResult | None:
            async with semaphore:
                if deadline is not None and time.monotonic() >= deadline:
                    return None
                return await self.attempt(adapter, payload)

        outcomes = await asyncio.gather(*(run(p) for p in payloads))
        results = [r for r in outcomes if r is not None]
        if len(results) < len(payloads):
            logger.warning(
                f"{self.name}: phase timeout reached after {len(results)}/{len(payloads)} payloads"
            )
        logger.info(
            f"{self.name}: {sum(r.succeeded for r in results)} succeeded, "
            f"{sum(r.status == AttackStatus.DEFENDED for r in results)} defended, "
            f"{len(results)} total"
        )
        return results

    def _result(self, payload: Payload, **fields: Any) -> AttackResult:
        """Build an AttackResult pre-filled with this module's and payload's metadata."""
        return AttackResult(
            module_name=self.name,
            aatck_id=self.aatck_id,
            technique_id=payload.technique_id,
            technique_name=payload.description,
            payload_used=payload.transcript,
            canary_token=payload.canary_token,
            remediation=self.remediation_for(payload.technique_id),
            metadata={"mutated": payload.mutated, "mutation_type": payload.mutation_type},
            **fields,
        )

    async def attempt(self, adapter: AgentAdapter, payload: Payload) -> AttackResult:
        """Run one payload (single- or multi-turn) in an isolated session."""
        from redclaw.core.observer import Observer

        try:
            session = adapter.fork()
            messages = payload.messages
            if len(messages) == 1:
                responses = [await session.send_message(messages[0])]
            else:
                responses = await session.send_multi_turn(messages)
        except Exception as exc:  # adapter bugs must not abort the whole campaign
            logger.error(f"{self.name}: {payload.technique_id} failed: {exc}")
            return self._result(
                payload, status=AttackStatus.ERROR, severity=Severity.INFO, evidence=str(exc)
            )

        ok_responses = [r for r in responses if r.ok]
        if not ok_responses:
            failed = responses[0] if responses else None
            error = "No response from target"
            if failed is not None:
                error = failed.error or f"HTTP {failed.status_code}"
            return self._result(
                payload, status=AttackStatus.ERROR, severity=Severity.INFO, evidence=error
            )

        observer = Observer()
        if payload.canary_token:
            observer.register_canary(payload.canary_token, payload.technique_id)
        observation = observer.observe(
            " ".join(r.text for r in ok_responses),
            [tc for r in ok_responses for tc in r.tool_calls],
        )

        if observation.compromised:
            return self._result(
                payload,
                status=AttackStatus.SUCCESS,
                severity=self.severity_for(payload.technique_id),
                confidence=self.success_confidence(observation),
                canary_detected=bool(observation.canary_hits),
                evidence=self.success_evidence(ok_responses, observation),
            )
        return self._result(
            payload,
            status=AttackStatus.DEFENDED,
            severity=Severity.INFO,
            confidence=self.DEFENDED_CONFIDENCE,
            evidence=self.defended_evidence(ok_responses),
        )

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------
    def severity_for(self, technique_id: str) -> Severity:
        return self.SEVERITY.get(technique_id, self.DEFAULT_SEVERITY)

    def remediation_for(self, technique_id: str) -> str:
        return self.REMEDIATION.get(technique_id, self.DEFAULT_REMEDIATION)

    def success_confidence(self, observation: ObservationResult) -> float:
        return 0.85 if observation.canary_hits else 0.5

    def success_evidence(
        self, responses: Sequence[AgentResponse], observation: ObservationResult
    ) -> str:
        parts: list[str] = []
        if len(responses) > 1:
            parts.append(f"Compromised after {len(responses)} turns.")
        if observation.canary_hits:
            tokens = ", ".join(sorted({h.token for h in observation.canary_hits}))
            parts.append(f"Canary detected: {tokens}")
        if observation.instruction_followed:
            parts.append("Agent appears to have followed injected instructions.")
        if observation.sensitive_data_leaked:
            parts.append("Sensitive data patterns detected in response.")
        if observation.behavioral_anomalies:
            parts.append(f"Anomalies: {'; '.join(observation.behavioral_anomalies[:3])}")
        parts.append(f"Response: {responses[-1].text[:300]}")
        return " | ".join(parts)

    def defended_evidence(self, responses: Sequence[AgentResponse]) -> str:
        prefix = f"Agent held across {len(responses)} turns. " if len(responses) > 1 else ""
        return f"{prefix}Agent response (defended): {responses[-1].text[:200]}"

    def generate_canary(self, prefix: str = "REDCLAW") -> str:
        """Generate a unique canary token for this attack."""
        uid = str(uuid.uuid4())[:8].upper()
        return f"{prefix}_CANARY_{uid}"


def build_multi_turn_payloads(
    sequences: list[dict[str, Any]], canary_prefix: str, canary_url: str = DEFAULT_CANARY_URL
) -> list[Payload]:
    """Turn ``{"technique_id", "description", "turns"}`` dicts into payloads."""
    from redclaw.payloads.generator import fill_template

    result: list[Payload] = []
    for seq in sequences:
        canary = f"{canary_prefix}_CANARY_{uuid.uuid4().hex[:8].upper()}"
        turns = [fill_template(t, canary, canary_url) for t in seq["turns"]]
        result.append(
            Payload(
                content=turns[-1],
                technique_id=seq["technique_id"],
                canary_token=canary,
                description=seq["description"],
                turns=turns,
            )
        )
    return result
