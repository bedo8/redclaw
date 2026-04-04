"""Scheduler — attack sequencing and phase management."""

from __future__ import annotations

from dataclasses import dataclass, field

from loguru import logger

from redclaw.attacks.base import AttackModule, AttackResult
from redclaw.config import CampaignPhase


# Module registry — maps identifiers to classes
_MODULE_REGISTRY: dict[str, type[AttackModule]] = {}


def register_module(identifier: str, module_class: type[AttackModule]) -> None:
    """Register an attack module class for use in campaigns."""
    _MODULE_REGISTRY[identifier] = module_class
    logger.debug(f"Registered attack module: {identifier}")


def get_module(identifier: str) -> AttackModule:
    """Instantiate a registered attack module by identifier."""
    cls = _MODULE_REGISTRY.get(identifier)
    if cls is None:
        raise KeyError(
            f"Unknown attack module: {identifier}. "
            f"Available: {list(_MODULE_REGISTRY.keys())}"
        )
    return cls()


def list_modules() -> list[dict[str, str]]:
    """List all registered attack modules."""
    modules = []
    for identifier, cls in _MODULE_REGISTRY.items():
        instance = cls()
        modules.append({
            "id": identifier,
            "name": instance.name,
            "aatck_ids": ", ".join(instance.aatck_ids),
            "description": instance.description,
        })
    return modules


@dataclass
class PhaseResult:
    """Results from a single campaign phase."""

    phase_name: str
    attack_results: list[AttackResult] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)

    @property
    def total_attacks(self) -> int:
        return len(self.attack_results)

    @property
    def successful_attacks(self) -> int:
        return sum(1 for r in self.attack_results if r.succeeded)

    @property
    def defended_attacks(self) -> int:
        from redclaw.attacks.base import AttackStatus
        return sum(1 for r in self.attack_results if r.status == AttackStatus.DEFENDED)


# ---------------------------------------------------------------------------
# Auto-register built-in modules
# ---------------------------------------------------------------------------
def _register_builtins() -> None:
    """Register all built-in attack modules."""
    from redclaw.attacks.prompt_injection import PromptInjectionModule
    from redclaw.attacks.tool_abuse import ToolAbuseModule
    from redclaw.attacks.context_poisoning import ContextPoisoningModule
    from redclaw.attacks.goal_hijacking import GoalHijackingModule
    from redclaw.attacks.mcp_exploitation import MCPExploitationModule
    from redclaw.attacks.data_exfiltration import DataExfiltrationModule
    from redclaw.attacks.cascading_compromise import CascadingCompromiseModule

    register_module("prompt_injection", PromptInjectionModule)
    register_module("tool_abuse", ToolAbuseModule)
    register_module("context_poisoning", ContextPoisoningModule)
    register_module("goal_hijacking", GoalHijackingModule)
    register_module("mcp_exploitation", MCPExploitationModule)
    register_module("data_exfiltration", DataExfiltrationModule)
    register_module("cascading_compromise", CascadingCompromiseModule)


_register_builtins()
