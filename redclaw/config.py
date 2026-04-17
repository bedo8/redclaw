"""RedClaw configuration models — Pydantic validated."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class AdapterType(str, Enum):
    """Supported agent adapter types."""

    HTTP = "http"
    OPENCLAW = "openclaw"
    MCP = "mcp"
    CLAUDE_API = "claude_api"


class CampaignPhase(BaseModel):
    """A single phase within a campaign."""

    name: str = Field(description="Phase name")
    attack_modules: list[str] = Field(description="Attack module identifiers to run")
    timeout_seconds: int = Field(default=300, ge=10)
    max_concurrent: int = Field(default=5, ge=1)


class CampaignConfig(BaseModel):
    """Campaign definition — loadable from YAML."""

    name: str
    description: str = ""
    version: str = "1.0"
    target_adapter: AdapterType = AdapterType.HTTP
    phases: list[CampaignPhase]
    payload_mutations: bool = Field(default=True, description="Enable payload mutation engine")
    max_total_attacks: int = Field(default=200, ge=1)
    declared_intent: bool = Field(
        default=False,
        description="Whether the agent is told it's being tested. Controls social engineering bias.",
    )


class TargetConfig(BaseModel):
    """Configuration for the target agent being assessed."""

    url: str = Field(description="Target agent URL or path")
    adapter: AdapterType = Field(default=AdapterType.HTTP)
    auth_header: str | None = Field(default=None, description="Authorization header value")
    auth_token: str | None = Field(default=None, description="Bearer token")
    timeout_seconds: int = Field(default=30, ge=5)
    verify_ssl: bool = Field(default=True)


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

    format: str = Field(default="html", pattern="^(html|json|both)$")
    output_dir: Path = Field(default=Path("reports"))
    include_payloads: bool = Field(default=True, description="Include payload details in report")
    include_evidence: bool = Field(default=True, description="Include agent responses as evidence")


class RedClawSettings(BaseSettings):
    """Global RedClaw settings — loaded from env vars and .env."""

    model_config = {"env_prefix": "REDCLAW_", "env_file": ".env", "extra": "ignore"}

    # LLM endpoint for payload mutation
    anthropic_base_url: str = Field(
        default="",
        description="AI endpoint base URL (e.g., OpenAI-compatible proxy)",
    )
    anthropic_api_key: str = Field(default="", description="AI endpoint API key")
    mutation_model: str = Field(
        default="claude-sonnet-4-6", description="Model for payload mutation"
    )

    # Canary server
    canary_host: str = Field(default="127.0.0.1", description="Canary server bind address")
    canary_port: int = Field(default=8299, ge=1024, le=65535)

    # Database
    db_path: Path = Field(default=Path("redclaw.db"), description="SQLite database path")

    # Logging
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    log_file: Path | None = Field(default=None)

    # Scoring
    scoring_weights: ScoringWeights = Field(default_factory=ScoringWeights)

    # Reporting
    report: ReportConfig = Field(default_factory=ReportConfig)
