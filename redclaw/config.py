"""RedClaw configuration models — Pydantic validated."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import AliasChoices, BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Model defaults for the Claude API adapter. Override with REDCLAW_CLAUDE_MODEL
# (or `--model` on the CLI); these constants are the only place they live.
# ---------------------------------------------------------------------------
CLAUDE_MODEL_DEFAULT = "claude-sonnet-5-5"
CLAUDE_MODEL_HEAVY = "claude-opus-5-5"
CLAUDE_MODEL_FAST = "claude-haiku-5-5"

CLAUDE_MODEL_ALIASES: dict[str, str] = {
    "default": CLAUDE_MODEL_DEFAULT,
    "heavy": CLAUDE_MODEL_HEAVY,
    "fast": CLAUDE_MODEL_FAST,
}


class AdapterType(StrEnum):
    """Supported agent adapter types."""

    HTTP = "http"
    OPENCLAW = "openclaw"
    MCP = "mcp"
    CLAUDE_API = "claude_api"


class ReportFormat(StrEnum):
    """Report output formats."""

    HTML = "html"
    JSON = "json"
    SARIF = "sarif"
    JUNIT = "junit"


class CampaignPhase(BaseModel):
    """A single phase within a campaign."""

    name: str = Field(description="Phase name")
    attack_modules: list[str] = Field(description="Attack module identifiers to run")
    timeout_seconds: int = Field(default=300, ge=10)
    max_concurrent: int = Field(
        default=5, ge=1, description="Maximum attack attempts in flight at once"
    )


class CampaignConfig(BaseModel):
    """Campaign definition — loadable from YAML."""

    name: str
    description: str = ""
    version: str = "1.0"
    target_adapter: AdapterType = AdapterType.HTTP
    phases: list[CampaignPhase]
    payload_mutations: bool = Field(default=True, description="Enable payload mutation engine")
    max_total_attacks: int = Field(default=200, ge=1)


class TargetConfig(BaseModel):
    """Configuration for the target agent being assessed."""

    url: str = Field(description="Target agent URL, MCP command line, or API base URL")
    adapter: AdapterType = Field(default=AdapterType.HTTP)
    auth_header: SecretStr | None = Field(
        default=None, description="Raw Authorization header value"
    )
    auth_token: SecretStr | None = Field(default=None, description="Bearer token / API key")
    timeout_seconds: int = Field(default=30, ge=1)
    verify_ssl: bool = Field(default=True)
    model: str | None = Field(
        default=None,
        description="Model name sent to OpenAI-compatible or Claude API targets",
    )
    system_prompt: str | None = Field(
        default=None, description="System prompt for the Claude API adapter"
    )
    mcp_tool: str | None = Field(
        default=None, description="MCP tool to call (defaults to the first listed tool)"
    )


class ScoringWeights(BaseModel):
    """Weights for the resilience score calculation."""

    prompt_injection: float = Field(default=0.20, ge=0, le=1)
    tool_abuse: float = Field(default=0.18, ge=0, le=1)
    context_integrity: float = Field(default=0.12, ge=0, le=1)
    goal_integrity: float = Field(default=0.10, ge=0, le=1)
    mcp_security: float = Field(default=0.10, ge=0, le=1)
    data_protection: float = Field(default=0.15, ge=0, le=1)
    multi_agent_isolation: float = Field(default=0.08, ge=0, le=1)
    social_engineering: float = Field(default=0.07, ge=0, le=1)


class ReportConfig(BaseModel):
    """Report generation settings."""

    include_payloads: bool = Field(default=True, description="Include payloads in reports")
    include_evidence: bool = Field(
        default=True, description="Include (redacted) agent responses as evidence"
    )


class RedClawSettings(BaseSettings):
    """Global RedClaw settings — loaded from ``REDCLAW_*`` env vars and ``.env``.

    Nested models use ``__`` as the delimiter, e.g.
    ``REDCLAW_SCORING_WEIGHTS__PROMPT_INJECTION=0.3`` or
    ``REDCLAW_REPORT__INCLUDE_PAYLOADS=false``.
    """

    model_config = SettingsConfigDict(
        env_prefix="REDCLAW_",
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Claude API adapter. The standard Anthropic variables are honored so the
    # SDK, the CLI and CI all read the same environment.
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("REDCLAW_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )
    anthropic_base_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("REDCLAW_ANTHROPIC_BASE_URL", "ANTHROPIC_BASE_URL"),
    )
    claude_model: str = Field(
        default=CLAUDE_MODEL_DEFAULT,
        description="Model for the Claude API adapter; 'default', 'heavy' and 'fast' are aliases",
    )

    # Out-of-band canary server (loopback only)
    canary_enabled: bool = Field(default=True)
    canary_host: str = Field(default="127.0.0.1", description="Canary server bind address")
    canary_port: int = Field(default=8299, ge=0, le=65535, description="0 picks a free port")
    canary_grace_seconds: float = Field(
        default=1.0, ge=0, description="Wait for late out-of-band requests before scoring"
    )

    # Logging
    log_level: str = Field(default="WARNING", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    log_file: Path | None = Field(default=None)

    # Scoring
    scoring_weights: ScoringWeights = Field(default_factory=ScoringWeights)

    # Reporting
    report: ReportConfig = Field(default_factory=ReportConfig)

    def resolved_claude_model(self, override: str | None = None) -> str:
        """Resolve the Claude model, expanding the default/heavy/fast aliases."""
        name = override or self.claude_model
        return CLAUDE_MODEL_ALIASES.get(name, name)
