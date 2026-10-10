"""RedClaw CLI — powered by Typer."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="redclaw",
    help="RedClaw — Adversarial AI Agent Red Team Framework",
    no_args_is_help=True,
)
console = Console()

# Sub-command groups
campaigns_app = typer.Typer(help="Campaign management")
attacks_app = typer.Typer(help="Attack module management")
app.add_typer(campaigns_app, name="campaigns")
app.add_typer(attacks_app, name="attacks")


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target agent URL"),
    adapter: str = typer.Option(
        "http", "--adapter", "-a", help="Adapter type (http, openclaw, mcp, claude_api)"
    ),
    campaign: str = typer.Option(
        "quick_prompt_injection", "--campaign", "-c", help="Campaign name or YAML path"
    ),
    output: str = typer.Option("reports", "--output", "-o", help="Output directory for reports"),
    no_mutations: bool = typer.Option(False, "--no-mutations", help="Disable payload mutations"),
    report_format: str = typer.Option(
        "html", "--format", "-f", help="Report format (html, json, both)"
    ),
) -> None:
    """Run an adversarial scan against a target AI agent."""
    asyncio.run(_run_scan(target, adapter, campaign, output, no_mutations, report_format))


async def _run_scan(
    target: str,
    adapter: str,
    campaign_name: str,
    output: str,
    no_mutations: bool,
    report_format: str,
) -> None:
    """Async scan implementation."""
    from redclaw.config import AdapterType, CampaignConfig, CampaignPhase, TargetConfig
    from redclaw.core.engine import CampaignEngine, load_campaign_from_yaml
    from redclaw.scoring.engine import ScoringEngine

    console.print("\n[bold red]RedClaw[/bold red] — Adversarial AI Agent Red Team Framework\n")

    # Load campaign
    campaign_path = _resolve_campaign(campaign_name)
    if campaign_path:
        campaign_config = load_campaign_from_yaml(campaign_path)
        console.print(f"  Campaign: [cyan]{campaign_config.name}[/cyan]")
    else:
        # Default quick campaign
        campaign_config = CampaignConfig(
            name=campaign_name,
            description="Quick scan",
            phases=[CampaignPhase(name="Prompt Injection", attack_modules=["prompt_injection"])],
        )
        console.print(f"  Campaign: [cyan]{campaign_name}[/cyan] (built-in)")

    if no_mutations:
        campaign_config.payload_mutations = False

    # Build target config
    target_config = TargetConfig(
        url=target,
        adapter=AdapterType(adapter),
    )
    console.print(f"  Target:   [cyan]{target}[/cyan]")
    console.print(f"  Adapter:  [cyan]{adapter}[/cyan]")
    console.print()

    # Run campaign
    engine = CampaignEngine(target_config, campaign_config)

    with console.status("[bold green]Running adversarial campaign..."):
        result = await engine.run()

    # Score results
    scorer = ScoringEngine()
    score = scorer.score(result.all_results)

    # Display results summary
    _display_results(result, score)

    # Generate report
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    from redclaw.reporting.generator import ReportGenerator

    generator = ReportGenerator(output_dir=output_dir)

    if report_format in ("html", "both"):
        html_path = generator.generate_html(result, score)
        console.print(f"\n  HTML report: [link=file://{html_path}]{html_path}[/link]")

    if report_format in ("json", "both"):
        json_path = generator.generate_json(result, score)
        console.print(f"  JSON report: [link=file://{json_path}]{json_path}[/link]")

    console.print()

    if not score.get("tested"):
        console.print(
            "[bold red]Scan inconclusive:[/bold red] every attack errored or was skipped. "
            "Check the target URL, adapter and credentials."
        )
        raise typer.Exit(2)


def _display_results(result, score) -> None:
    """Display campaign results in a rich table."""
    console.print()

    # Score card
    grade_color = {
        "A": "green",
        "B": "blue",
        "C": "yellow",
        "D": "red",
        "F": "bold red",
    }.get(score["grade"], "white")

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
    console.print(f"  Duration: {result.duration_seconds:.1f}s")

    # Dimension breakdown
    console.print()
    table = Table(title="Resilience Dimensions", show_lines=True)
    table.add_column("Dimension", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Weight", justify="right")
    table.add_column("Attacks", justify="right")

    for dim in score.get("dimensions", []):
        if dim["score"] is None:
            label = "all errored" if dim.get("errors") else "not tested"
            table.add_row(dim["name"], f"[dim]{label}[/dim]", f"{dim['weight']:.0%}", "0")
        else:
            score_color = (
                "green" if dim["score"] >= 75 else "yellow" if dim["score"] >= 50 else "red"
            )
            table.add_row(
                dim["name"],
                f"[{score_color}]{dim['score']:.0f}[/{score_color}]",
                f"{dim['weight']:.0%}",
                str(dim["attacks"]),
            )

    console.print(table)

    # Critical findings
    critical_results = [
        r for r in result.all_results if r.succeeded and r.severity.value in ("CRITICAL", "HIGH")
    ]
    if critical_results:
        console.print()
        findings_table = Table(title="Critical Findings", show_lines=True)
        findings_table.add_column("AATCK ID", style="red")
        findings_table.add_column("Technique")
        findings_table.add_column("Severity")
        findings_table.add_column("Evidence", max_width=60)

        for r in critical_results[:10]:
            sev_color = "bold red" if r.severity.value == "CRITICAL" else "yellow"
            findings_table.add_row(
                r.technique_id,
                r.technique_name,
                f"[{sev_color}]{r.severity.value}[/{sev_color}]",
                r.evidence[:60],
            )

        console.print(findings_table)


@app.command()
def report(
    input_file: str = typer.Option(
        "reports/latest.json", "--input", "-i", help="Input JSON results"
    ),
    output: str = typer.Option("reports", "--output", "-o", help="Output directory"),
    report_format: str = typer.Option("html", "--format", "-f", help="Report format (html, json)"),
) -> None:
    """Generate a report from previous scan results."""
    import json
    from dataclasses import dataclass, field

    from redclaw.attacks.base import AttackResult, AttackStatus, Severity
    from redclaw.reporting.generator import ReportGenerator

    console.print("[bold red]RedClaw[/bold red] — Report Generator\n")

    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"  [red]Error: {input_file} not found.[/red]")
        raise typer.Exit(1)

    console.print(f"  Input: {input_path}")

    data = json.loads(input_path.read_text(encoding="utf-8"))
    meta = data.get("meta", {})
    score = data.get("score", {})

    # Reconstruct AttackResult objects from JSON findings
    results: list[AttackResult] = []
    for f in data.get("findings", []):
        results.append(
            AttackResult(
                attack_id=f.get("attack_id", ""),
                module_name=f.get("module", ""),
                aatck_id=f.get("aatck_id", ""),
                technique_id=f.get("technique_id", ""),
                technique_name=f.get("technique_name", ""),
                status=AttackStatus(f.get("status", "defended")),
                severity=Severity(f.get("severity", "MEDIUM")),
                confidence=f.get("confidence", 0.0),
                canary_detected=f.get("canary_detected", False),
                evidence=f.get("evidence", ""),
                remediation=f.get("remediation", ""),
                payload_used=f.get("payload", ""),
            )
        )

    # Lightweight stand-in for CampaignResult
    @dataclass
    class _LoadedResult:
        campaign_name: str
        target_url: str
        adapter_type: str
        duration_seconds: float
        all_results: list[AttackResult] = field(default_factory=list)

    loaded = _LoadedResult(
        campaign_name=meta.get("campaign", "unknown"),
        target_url=meta.get("target", "unknown"),
        adapter_type=meta.get("adapter", "unknown"),
        duration_seconds=meta.get("duration_seconds", 0.0),
        all_results=results,
    )

    output_dir = Path(output)
    generator = ReportGenerator(output_dir=output_dir)
    html_path = generator.generate_html(loaded, score)
    console.print(f"  HTML report: [link=file://{html_path}]{html_path}[/link]")
    console.print("  [green]Done.[/green]")


@campaigns_app.command("list")
def campaigns_list() -> None:
    """List available campaigns."""
    campaign_dirs = [
        Path(__file__).parent.parent / "campaigns",
        Path.cwd() / "campaigns",
    ]

    table = Table(title="Available Campaigns")
    table.add_column("Name", style="cyan")
    table.add_column("File")
    table.add_column("Description", max_width=50)

    for campaign_dir in campaign_dirs:
        if not campaign_dir.exists():
            continue
        for f in sorted(campaign_dir.glob("*.yaml")):
            import yaml

            with f.open() as fh:
                data = yaml.safe_load(fh)
            table.add_row(
                data.get("name", f.stem),
                str(f.name),
                data.get("description", "")[:50],
            )

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
        table.add_row(mod["id"], mod["name"], mod["aatck_ids"], mod["description"][:50])

    console.print(table)


@app.command()
def dashboard(
    port: int = typer.Option(8200, "--port", "-p", help="Dashboard port"),
    reports_dir: str = typer.Option("reports", "--reports", "-r", help="Reports directory"),
) -> None:
    """Start the RedClaw results dashboard."""
    console.print("\n[bold red]RedClaw[/bold red] Dashboard")
    console.print(f"  URL: [link=http://127.0.0.1:{port}]http://127.0.0.1:{port}[/link]")
    console.print(f"  Reports: {reports_dir}\n")

    from redclaw.reporting.dashboard import run_dashboard

    run_dashboard(port=port, reports_dir=reports_dir)


def _resolve_campaign(name: str) -> Path | None:
    """Resolve a campaign name to a YAML file path."""
    # Direct path
    direct = Path(name)
    if direct.exists() and direct.suffix in (".yaml", ".yml"):
        return direct

    # Check built-in campaigns
    builtin_dir = Path(__file__).parent.parent / "campaigns"
    for candidate in [
        builtin_dir / f"{name}.yaml",
        builtin_dir / f"{name}.yml",
    ]:
        if candidate.exists():
            return candidate

    # Check CWD campaigns
    cwd_dir = Path.cwd() / "campaigns"
    for candidate in [
        cwd_dir / f"{name}.yaml",
        cwd_dir / f"{name}.yml",
    ]:
        if candidate.exists():
            return candidate

    return None


if __name__ == "__main__":
    app()
