"""RedClaw CLI — powered by Typer."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from redclaw.version import __version__

app = typer.Typer(
    name="redclaw",
    help="RedClaw — Adversarial AI Agent Red Team Framework",
    no_args_is_help=True,
)
console = Console()

campaigns_app = typer.Typer(help="Campaign management")
attacks_app = typer.Typer(help="Attack module management")
app.add_typer(campaigns_app, name="campaigns")
app.add_typer(attacks_app, name="attacks")

FORMAT_HELP = "Comma-separated report formats: html, json, sarif, junit, or 'all'"

# Exit codes
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_INCONCLUSIVE = 2
EXIT_FINDINGS = 3


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"redclaw {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    log_level: str | None = typer.Option(
        None,
        "--log-level",
        help="DEBUG, INFO, WARNING, ERROR (default: REDCLAW_LOG_LEVEL or WARNING)",
    ),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version"
    ),
) -> None:
    """RedClaw — Adversarial AI Agent Red Team Framework."""
    from redclaw._logging import configure_logging
    from redclaw.config import RedClawSettings

    settings = RedClawSettings()
    configure_logging(log_level or settings.log_level, settings.log_file)


@app.command()
def scan(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target URL (http/openclaw), MCP command line or http(s) URL (mcp), "
        "or API base URL (claude_api; empty string uses ANTHROPIC_BASE_URL)",
    ),
    adapter: str = typer.Option(
        "http", "--adapter", "-a", help="Adapter type: http, openclaw, mcp, claude_api"
    ),
    campaign: str = typer.Option(
        "quick_prompt_injection", "--campaign", "-c", help="Campaign name or YAML path"
    ),
    output: Path = typer.Option(Path("reports"), "--output", "-o", help="Report directory"),
    report_format: str = typer.Option("html,json", "--format", "-f", help=FORMAT_HELP),
    no_mutations: bool = typer.Option(False, "--no-mutations", help="Disable payload mutations"),
    auth_token: str | None = typer.Option(
        None,
        "--auth-token",
        envvar="REDCLAW_AUTH_TOKEN",
        help="Bearer token / API key for the target (env: REDCLAW_AUTH_TOKEN)",
        show_default=False,
    ),
    insecure: bool = typer.Option(
        False, "--insecure", help="Skip TLS certificate verification for the target"
    ),
    timeout: int = typer.Option(30, "--timeout", min=1, help="Per-request timeout (seconds)"),
    model: str | None = typer.Option(
        None,
        "--model",
        help="Model for claude_api (or 'default'/'heavy'/'fast') and OpenAI-compatible targets",
    ),
    system_prompt: str | None = typer.Option(
        None, "--system-prompt", help="System prompt for the claude_api adapter"
    ),
    mcp_tool: str | None = typer.Option(
        None, "--mcp-tool", help="MCP tool to send payloads to (default: first listed tool)"
    ),
    canary: bool = typer.Option(
        True, "--canary/--no-canary", help="Run the loopback canary server for exfil detection"
    ),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings", help=f"Exit {EXIT_FINDINGS} if any attack succeeded"
    ),
    seed: int | None = typer.Option(
        None,
        "--seed",
        help="Seed payload mutations so repeated scans send the same variants (useful in CI)",
    ),
) -> None:
    """Run an adversarial scan against a target AI agent."""
    from pydantic import SecretStr

    from redclaw.campaigns import CampaignLoadError, CampaignNotFoundError, resolve_campaign
    from redclaw.config import AdapterType, RedClawSettings, TargetConfig
    from redclaw.reporting.generator import parse_formats

    try:
        formats = parse_formats(report_format)
        adapter_type = AdapterType(adapter)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_USAGE) from None

    try:
        campaign_config = resolve_campaign(campaign)
    except (CampaignNotFoundError, CampaignLoadError) as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_USAGE) from None
    if no_mutations:
        campaign_config.payload_mutations = False
    if seed is not None:
        import random

        random.seed(seed)

    settings = RedClawSettings()
    if not canary:
        settings.canary_enabled = False

    target_config = TargetConfig(
        url=target,
        adapter=adapter_type,
        auth_token=SecretStr(auth_token) if auth_token else None,
        verify_ssl=not insecure,
        timeout_seconds=timeout,
        model=model,
        system_prompt=system_prompt,
        mcp_tool=mcp_tool,
    )

    code = asyncio.run(
        _run_scan(target_config, campaign_config, settings, output, formats, fail_on_findings)
    )
    raise typer.Exit(code)


async def _run_scan(
    target_config: Any,
    campaign_config: Any,
    settings: Any,
    output: Path,
    formats: list[Any],
    fail_on_findings: bool,
) -> int:
    from redclaw.core.engine import CampaignEngine
    from redclaw.reporting.generator import ReportGenerator
    from redclaw.scoring.engine import ScoringEngine

    console.print("\n[bold]RedClaw[/bold] — Adversarial AI Agent Red Team Framework\n")
    console.print(f"  Campaign: [cyan]{escape(campaign_config.name)}[/cyan]")
    console.print(f"  Target:   [cyan]{escape(target_config.url)}[/cyan]")
    console.print(f"  Adapter:  [cyan]{target_config.adapter.value}[/cyan]\n")

    engine = CampaignEngine(target_config, campaign_config, settings=settings)
    with console.status("[bold green]Running adversarial campaign..."):
        result = await engine.run()

    score = ScoringEngine(settings.scoring_weights).score(result.all_results)
    _display_results(result, score)

    secrets = [
        s.get_secret_value()
        for s in (target_config.auth_token, target_config.auth_header, settings.anthropic_api_key)
        if s is not None
    ]
    generator = ReportGenerator(output_dir=output, report_config=settings.report, secrets=secrets)
    paths = generator.generate(result, score, formats)
    console.print()
    for fmt, path in paths.items():
        console.print(f"  {fmt.value.upper():5} report: {escape(str(path))}")
    console.print()

    if result.metadata.get("error"):
        console.print(f"[red]Engine error:[/red] {escape(str(result.metadata['error']))}")
    if not score.get("tested"):
        console.print(
            "[bold red]Scan inconclusive:[/bold red] every attack errored or was skipped. "
            "Check the target URL, adapter and credentials."
        )
        return EXIT_INCONCLUSIVE
    if fail_on_findings and score.get("total_succeeded", 0) > 0:
        return EXIT_FINDINGS
    return EXIT_OK


def _display_results(result: Any, score: dict[str, Any]) -> None:
    """Display campaign results in rich tables."""
    grade_color = {"A": "green", "B": "blue", "C": "yellow", "D": "red", "F": "bold red"}.get(
        score["grade"], "white"
    )
    if score["overall_score"] is None:
        console.print(
            "  Resilience Score: [bold yellow]not tested[/bold yellow] — no attack reached "
            "the target and produced a verdict"
        )
    else:
        console.print(
            f"  Resilience Score: [{grade_color}]{score['overall_score']:.0f}/100 "
            f"(Grade: {score['grade']})[/{grade_color}]"
        )
    console.print(f"  Total Attacks: {result.total_attacks}")
    console.print(f"  Succeeded: [red]{result.successful_attacks}[/red]")
    console.print(f"  Defended: [green]{result.defended_attacks}[/green]")
    console.print(f"  Errors: [yellow]{score.get('total_errors', 0)}[/yellow]")
    if result.metadata.get("out_of_band_hits"):
        console.print(
            f"  Out-of-band canary hits: [red]{result.metadata['out_of_band_hits']}[/red]"
        )
    console.print(f"  Duration: {result.duration_seconds:.1f}s\n")

    table = Table(title="Resilience Dimensions", show_lines=True)
    table.add_column("Dimension", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Weight", justify="right")
    table.add_column("Evaluated", justify="right")
    table.add_column("Errors", justify="right")
    for dim in score.get("dimensions", []):
        if dim["score"] is None:
            label = "all errored" if dim.get("errors") else "not tested"
            score_cell = f"[dim]{label}[/dim]"
        else:
            color = "green" if dim["score"] >= 75 else "yellow" if dim["score"] >= 50 else "red"
            score_cell = f"[{color}]{dim['score']:.0f}[/{color}]"
        table.add_row(
            dim["name"],
            score_cell,
            f"{dim['weight']:.0%}",
            str(dim["attacks"]),
            str(dim.get("errors", 0)),
        )
    console.print(table)

    critical = [
        r for r in result.all_results if r.succeeded and r.severity.value in ("CRITICAL", "HIGH")
    ]
    if critical:
        from redclaw.reporting.redaction import redact

        findings_table = Table(title="Critical Findings", show_lines=True)
        findings_table.add_column("Technique", style="red")
        findings_table.add_column("Name")
        findings_table.add_column("Severity")
        findings_table.add_column("Evidence", max_width=60)
        for r in critical[:10]:
            findings_table.add_row(
                r.technique_id,
                escape(r.technique_name),
                r.severity.value,
                escape(redact(r.evidence)[:60]),
            )
        console.print()
        console.print(findings_table)


@app.command()
def report(
    input_file: Path = typer.Option(
        Path("reports/latest.json"), "--input", "-i", help="JSON report from a previous scan"
    ),
    output: Path = typer.Option(Path("reports"), "--output", "-o", help="Output directory"),
    report_format: str = typer.Option("html", "--format", "-f", help=FORMAT_HELP),
) -> None:
    """Re-render a saved JSON report as HTML, SARIF, JUnit or JSON."""
    from redclaw.reporting.document import validate_document
    from redclaw.reporting.generator import ReportGenerator, parse_formats

    try:
        formats = parse_formats(report_format)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_USAGE) from None

    if not input_file.is_file():
        console.print(f"[red]Error:[/red] {escape(str(input_file))} not found.")
        raise typer.Exit(EXIT_USAGE)

    try:
        doc = validate_document(json.loads(input_file.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {escape(str(input_file))}: {escape(str(exc))}")
        raise typer.Exit(EXIT_USAGE) from None

    generator = ReportGenerator(output_dir=output)
    for fmt in formats:
        path = generator.write(doc, fmt)
        console.print(f"  {fmt.value.upper():5} report: {escape(str(path))}")


@campaigns_app.command("list")
def campaigns_list() -> None:
    """List built-in campaigns and any YAML campaigns in ./campaigns."""
    from redclaw.campaigns import list_campaigns

    table = Table(title="Available Campaigns")
    table.add_column("Key", style="cyan")
    table.add_column("Name")
    table.add_column("Source")
    table.add_column("Description", max_width=50)
    for info in list_campaigns():
        table.add_row(info.key, escape(info.name), escape(info.source), escape(info.description))
    console.print(table)


@attacks_app.command("list")
def attacks_list() -> None:
    """List available attack modules."""
    from redclaw.core.scheduler import list_modules

    table = Table(title="Available Attack Modules")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("AATCK IDs", style="red")
    table.add_column("Description", max_width=50)
    for mod in list_modules():
        table.add_row(mod["id"], mod["name"], mod["aatck_ids"], mod["description"])
    console.print(table)


@app.command()
def dashboard(
    port: int = typer.Option(8200, "--port", "-p", help="Dashboard port"),
    reports_dir: str = typer.Option("reports", "--reports", "-r", help="Reports directory"),
) -> None:
    """Start the results dashboard (needs the 'dashboard' extra)."""
    import importlib.util

    if not all(importlib.util.find_spec(m) for m in ("fastapi", "uvicorn")):
        console.print(
            "[red]Error:[/red] the dashboard needs extra packages: "
            "pip install 'redclaw\\[dashboard]'"
        )
        raise typer.Exit(EXIT_USAGE)

    from redclaw.reporting import dashboard as dashboard_module

    console.print("\n[bold]RedClaw[/bold] Dashboard")
    console.print(f"  URL: http://127.0.0.1:{port}")
    console.print(f"  Reports: {escape(reports_dir)}\n")
    dashboard_module.run_dashboard(port=port, reports_dir=reports_dir)


if __name__ == "__main__":
    app()
