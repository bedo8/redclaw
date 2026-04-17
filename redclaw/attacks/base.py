"""Base classes for all RedClaw attack modules."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redclaw.adapters.base import AgentAdapter
    from redclaw.config import TargetConfig


class Severity(str, Enum):
    """Attack finding severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AttackStatus(str, Enum):
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
    remediation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        """Whether this attack compromised the target."""
        return self.status == AttackStatus.SUCCESS


@dataclass
class Payload:
    """A single attack payload with metadata."""

    content: str
    technique_id: str
    canary_token: str = ""
    description: str = ""
    mutated: bool = False
    mutation_type: str = ""


class AttackModule(ABC):
    """Abstract base class for all RedClaw attack modules.

    Every attack module must implement:
    - name: Human-readable module name
    - aatck_ids: Which AATCK classes this module tests
    - description: What this module does
    - payloads: Generate attack payloads
    - execute: Run attacks against a target via an adapter
    """

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

    @abstractmethod
    async def execute(
        self,
        adapter: AgentAdapter,
        target_config: TargetConfig,
    ) -> list[AttackResult]:
        """Run all attacks in this module against the target.

        Args:
            adapter: Agent communication adapter.
            target_config: Target agent configuration.

        Returns:
            List of AttackResult for each attack attempted.
        """

    def generate_canary(self, prefix: str = "REDCLAW") -> str:
        """Generate a unique canary token for this attack."""
        uid = str(uuid.uuid4())[:8].upper()
        return f"{prefix}_CANARY_{uid}"
