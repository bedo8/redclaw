"""AATCK — Adversarial AI Tactics, Techniques & Kill Chain.

The complete taxonomy as Python dataclasses for programmatic use
in scoring, reporting, and attack module mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Attack severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Technique:
    """A specific attack technique within an AATCK class."""

    id: str
    name: str
    description: str


@dataclass(frozen=True)
class AATCKClass:
    """An AATCK attack class containing multiple techniques."""

    id: str
    name: str
    description: str
    severity_range: tuple[Severity, Severity]
    target: str
    techniques: tuple[Technique, ...]
    detection: tuple[str, ...]
    remediation: tuple[str, ...]


# ---------------------------------------------------------------------------
# AATCK-001: Prompt Injection
# ---------------------------------------------------------------------------
AATCK_001 = AATCKClass(
    id="AATCK-001",
    name="Prompt Injection",
    description="Inject adversarial instructions through data channels the agent processes.",
    severity_range=(Severity.HIGH, Severity.CRITICAL),
    target="Agent instruction-following boundary",
    techniques=(
        Technique("AATCK-001.T01", "Direct Override", "Plaintext instruction override in user message."),
        Technique("AATCK-001.T02", "Indirect Injection", "Malicious instructions embedded in fetched data."),
        Technique("AATCK-001.T03", "Delimiter Escape", "Use markdown/XML/system delimiters to break context."),
        Technique("AATCK-001.T04", "Encoding Evasion", "Base64, Unicode homoglyphs, ROT13 obfuscation."),
        Technique("AATCK-001.T05", "Role Injection", "Redefine agent identity via role-play framing."),
        Technique("AATCK-001.T06", "Instruction Smuggling", "Hide instructions in seemingly benign content."),
        Technique("AATCK-001.T07", "Payload Splitting", "Split malicious instruction across multiple messages."),
        Technique("AATCK-001.T08", "Few-Shot Poisoning", "Fake examples that lead agent into unsafe patterns."),
    ),
    detection=(
        "Monitor for instruction-like patterns in data channels.",
        "Track behavioral deviation after processing external data.",
        "Canary token presence in agent responses.",
    ),
    remediation=(
        "Implement strict input/data boundary separation.",
        "Use dedicated system prompts that cannot be overridden.",
        "Apply content filtering on all data channels.",
        "Deploy instruction hierarchy (system > user > data).",
    ),
)

# ---------------------------------------------------------------------------
# AATCK-002: Tool Abuse
# ---------------------------------------------------------------------------
AATCK_002 = AATCKClass(
    id="AATCK-002",
    name="Tool Abuse",
    description="Manipulate an agent into misusing its own tools.",
    severity_range=(Severity.HIGH, Severity.CRITICAL),
    target="Agent tool execution capabilities",
    techniques=(
        Technique("AATCK-002.T01", "Path Traversal", "Coerce file operations to sensitive paths."),
        Technique("AATCK-002.T02", "HTTP Exfiltration", "Trick agent into sending data to attacker endpoints."),
        Technique("AATCK-002.T03", "Shell Injection", "Inject shell metacharacters into tool parameters."),
        Technique("AATCK-002.T04", "Tool Chain Attack", "Chain legitimate tool calls for malicious outcome."),
        Technique("AATCK-002.T05", "Parameter Pollution", "Overloaded parameters that change tool behavior."),
        Technique("AATCK-002.T06", "Privilege Escalation via Tools", "Access resources beyond intended scope."),
    ),
    detection=(
        "Audit tool calls for sensitive paths, external URLs, shell metacharacters.",
        "Enforce allowlists for file paths, HTTP destinations, commands.",
        "Monitor tool call sequences for unusual patterns.",
    ),
    remediation=(
        "Implement strict tool parameter validation and sanitization.",
        "Use allowlists (not blocklists) for file paths and HTTP destinations.",
        "Sandbox tool execution environments.",
        "Require human approval for high-risk tool operations.",
    ),
)

# ---------------------------------------------------------------------------
# AATCK-003: Context Poisoning
# ---------------------------------------------------------------------------
AATCK_003 = AATCKClass(
    id="AATCK-003",
    name="Context Poisoning",
    description="Corrupt the agent's context window over multiple turns.",
    severity_range=(Severity.MEDIUM, Severity.HIGH),
    target="Agent working memory and conversation context",
    techniques=(
        Technique("AATCK-003.T01", "Gradual Trust Escalation", "Slowly escalate from benign to restricted requests."),
        Technique("AATCK-003.T02", "Persona Drift", "Redefine agent role through conversational framing."),
        Technique("AATCK-003.T03", "False Memory Implantation", "Insert false claims about prior conversations."),
        Technique("AATCK-003.T04", "Context Flooding", "Fill context window with noise to push out instructions."),
        Technique("AATCK-003.T05", "Authority Spoofing", "Claim admin/developer role to gain elevated trust."),
    ),
    detection=(
        "Track persona consistency across turns.",
        "Monitor for escalation patterns in request sensitivity.",
        "Detect context window saturation attempts.",
        "Flag claims about prior conversations that don't match history.",
    ),
    remediation=(
        "Implement persistent system instructions that survive context manipulation.",
        "Use separate protected memory for core instructions.",
        "Limit context window influence on safety-critical decisions.",
        "Validate authority claims against actual authentication.",
    ),
)

# ---------------------------------------------------------------------------
# AATCK-004: Goal Hijacking
# ---------------------------------------------------------------------------
AATCK_004 = AATCKClass(
    id="AATCK-004",
    name="Goal Hijacking",
    description="Redirect the agent from its intended mission.",
    severity_range=(Severity.MEDIUM, Severity.CRITICAL),
    target="Agent objective function and task prioritization",
    techniques=(
        Technique("AATCK-004.T01", "Priority Inversion", "Present fabricated urgent task superseding real mission."),
        Technique("AATCK-004.T02", "Alert Fatigue Exploitation", "Flood false positives to make agent ignore real alerts."),
        Technique("AATCK-004.T03", "Objective Reframing", "Redefine what 'success' means for the agent's task."),
        Technique("AATCK-004.T04", "Distraction Injection", "Insert irrelevant tasks that consume agent resources."),
    ),
    detection=(
        "Monitor task completion rates against expected baselines.",
        "Track objective drift over time.",
        "Alert on sudden priority changes without legitimate triggers.",
    ),
    remediation=(
        "Hardcode mission-critical objectives that cannot be overridden.",
        "Implement objective validation against a static mission definition.",
        "Use separate channels for mission-critical vs. general input.",
    ),
)

# ---------------------------------------------------------------------------
# AATCK-005: MCP Exploitation
# ---------------------------------------------------------------------------
AATCK_005 = AATCKClass(
    id="AATCK-005",
    name="MCP Exploitation",
    description="Attack through the Model Context Protocol layer.",
    severity_range=(Severity.HIGH, Severity.CRITICAL),
    target="MCP server connections, tool descriptions, tool responses",
    techniques=(
        Technique("AATCK-005.T01", "Tool Description Injection", "Embed instructions in MCP tool descriptions."),
        Technique("AATCK-005.T02", "Poisoned Tool Response", "Return malicious instructions in tool response data."),
        Technique("AATCK-005.T03", "Tool Name Spoofing", "Register tool mimicking a trusted tool name."),
        Technique("AATCK-005.T04", "Excessive Permission Tool", "Offer tools with overly broad capabilities."),
        Technique("AATCK-005.T05", "Schema Manipulation", "Return data mismatching declared schema."),
    ),
    detection=(
        "Validate MCP tool descriptions for instruction-like content.",
        "Verify tool response schemas match declarations.",
        "Monitor for duplicate or similar tool names across servers.",
    ),
    remediation=(
        "Validate and sanitize all MCP tool responses.",
        "Implement MCP server allowlists.",
        "Enforce schema validation on tool responses.",
        "Require explicit user approval for new MCP server connections.",
    ),
)

# ---------------------------------------------------------------------------
# AATCK-006: Data Exfiltration
# ---------------------------------------------------------------------------
AATCK_006 = AATCKClass(
    id="AATCK-006",
    name="Data Exfiltration",
    description="Coerce the agent into revealing sensitive data.",
    severity_range=(Severity.HIGH, Severity.CRITICAL),
    target="Agent access to sensitive data",
    techniques=(
        Technique("AATCK-006.T01", "System Prompt Extraction", "Trick agent into revealing its system prompt."),
        Technique("AATCK-006.T02", "Credential Harvesting", "Coerce agent into exposing API keys or tokens."),
        Technique("AATCK-006.T03", "Indirect Exfiltration", "Agent includes sensitive data in tool calls."),
        Technique("AATCK-006.T04", "Training Data Extraction", "Extract memorized training data."),
        Technique("AATCK-006.T05", "Cross-Conversation Leakage", "Extract info from other users' sessions."),
    ),
    detection=(
        "Monitor responses for credential patterns.",
        "Scan tool call parameters for sensitive data.",
        "Track information disclosure patterns across sessions.",
    ),
    remediation=(
        "Never include credentials in agent context — use secret managers.",
        "Implement output filtering for credential patterns.",
        "Separate data access permissions from response generation.",
        "Deploy canary tokens to detect exfiltration.",
    ),
)

# ---------------------------------------------------------------------------
# AATCK-007: Cascading Compromise
# ---------------------------------------------------------------------------
AATCK_007 = AATCKClass(
    id="AATCK-007",
    name="Cascading Compromise",
    description="Compromise one agent to attack others in multi-agent systems.",
    severity_range=(Severity.CRITICAL, Severity.CRITICAL),
    target="Inter-agent communication and trust relationships",
    techniques=(
        Technique("AATCK-007.T01", "Sub-Agent Poisoning", "Compromise sub-agent to manipulate orchestrator."),
        Technique("AATCK-007.T02", "Credential Relay", "Use compromised agent's credentials for lateral movement."),
        Technique("AATCK-007.T03", "Trust Chain Exploitation", "Exploit implicit trust between agents."),
        Technique("AATCK-007.T04", "Orchestrator Manipulation", "Target orchestrator to control entire workflow."),
    ),
    detection=(
        "Validate sub-agent outputs against expected schemas.",
        "Monitor inter-agent communication for anomalies.",
        "Implement mutual authentication between agents.",
    ),
    remediation=(
        "Treat all inter-agent communication as untrusted input.",
        "Implement zero-trust between agents.",
        "Use separate credentials per agent with minimal scope.",
        "Deploy output validation at every agent boundary.",
    ),
)

# ---------------------------------------------------------------------------
# Registry — all classes indexed by ID
# ---------------------------------------------------------------------------
AATCK_REGISTRY: dict[str, AATCKClass] = {
    c.id: c
    for c in (AATCK_001, AATCK_002, AATCK_003, AATCK_004, AATCK_005, AATCK_006, AATCK_007)
}

ALL_TECHNIQUES: dict[str, Technique] = {
    t.id: t for c in AATCK_REGISTRY.values() for t in c.techniques
}


def get_class(aatck_id: str) -> AATCKClass:
    """Look up an AATCK class by ID (e.g. 'AATCK-001')."""
    cls = AATCK_REGISTRY.get(aatck_id)
    if cls is None:
        raise KeyError(f"Unknown AATCK class: {aatck_id}")
    return cls


def get_technique(technique_id: str) -> Technique:
    """Look up a technique by ID (e.g. 'AATCK-001.T03')."""
    tech = ALL_TECHNIQUES.get(technique_id)
    if tech is None:
        raise KeyError(f"Unknown AATCK technique: {technique_id}")
    return tech
