"""Command line interface for AgentGuard."""

import json
import sys
from pathlib import Path
import click
from rich.console import Console

from agentguard.engine import evaluate_trace, get_default_evaluators
from agentguard.evaluators.schema_validator import SchemaValidator
from agentguard.models import AgentTrace, Severity
from agentguard.redteam.fuzzer import AgentRedTeamFuzzer
from agentguard.reporters.console import render_console_report
from agentguard.reporters.junit import render_junit_report
from agentguard.reporters.sarif import render_sarif_report


@click.group()
@click.version_option(version="0.1.0", prog_name="agentguard")
def cli():
    """AgentGuard: Deterministic Security & Reliability Evaluation Framework for AI Agents."""
    pass


@cli.command("evaluate")
@click.argument("trace_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["console", "junit", "sarif"], case_sensitive=False),
    default="console",
    help="Output report format (default: console).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional file path to write the output report.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["ANY", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default="ANY",
    help="Severity threshold to trigger non-zero exit code (default: ANY).",
)
@click.option(
    "--schema",
    "-s",
    "schema_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to JSON file with tool JSON schemas.",
)
def evaluate_cmd(trace_file: Path, report_format: str, output: Path, fail_on: str, schema_file: Path):
    """Evaluate an agent execution trace against security and reliability rules."""
    try:
        with open(trace_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        trace = AgentTrace.model_validate(data)
    except Exception as e:
        click.secho(f"Error parsing trace file '{trace_file}': {e}", fg="red", err=True)
        sys.exit(2)

    evaluators = get_default_evaluators()

    if schema_file:
        try:
            with open(schema_file, "r", encoding="utf-8") as f:
                schemas = json.load(f)
            # Find and configure schema validator
            for ev in evaluators:
                if isinstance(ev, SchemaValidator):
                    ev.tool_schemas = schemas
        except Exception as e:
            click.secho(f"Error reading schema file '{schema_file}': {e}", fg="red", err=True)
            sys.exit(2)

    result = evaluate_trace(trace, evaluators)

    # Format output
    if report_format == "console":
        if output:
            txt = render_console_report(result)
            output.write_text(txt, encoding="utf-8")
            click.echo(f"Report written to {output}")
        else:
            render_console_report(result, console=Console())
    elif report_format == "junit":
        xml_content = render_junit_report(result)
        if output:
            output.write_text(xml_content, encoding="utf-8")
            click.echo(f"JUnit XML written to {output}")
        else:
            click.echo(xml_content)
    elif report_format == "sarif":
        sarif_content = render_sarif_report(result)
        if output:
            output.write_text(sarif_content, encoding="utf-8")
            click.echo(f"SARIF JSON written to {output}")
        else:
            click.echo(sarif_content)

    # Determine exit code based on --fail-on
    severity_order = {
        "ANY": [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
        "MEDIUM": [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
        "HIGH": [Severity.HIGH, Severity.CRITICAL],
        "CRITICAL": [Severity.CRITICAL],
    }
    target_severities = set(severity_order.get(fail_on.upper(), severity_order["ANY"]))

    should_fail = any(f.severity in target_severities for f in result.findings)
    if should_fail:
        sys.exit(1)


@cli.command("fuzz")
@click.argument("prompt", type=str)
@click.option("--tool", default="bash_execute", help="Target tool name hint for attacks.")
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional file path to save generated adversarial test cases.",
)
def fuzz_cmd(prompt: str, tool: str, output: Path):
    """Generate red-team adversarial prompt injection and jailbreak test cases."""
    fuzzer = AgentRedTeamFuzzer()
    test_cases = fuzzer.generate_adversarial_prompts(prompt, tool_hint=tool)

    console = Console()
    console.print(f"[bold cyan]Generated {len(test_cases)} Adversarial Attack Test Cases[/bold cyan]\n")

    for idx, tc in enumerate(test_cases, 1):
        console.print(f"[bold yellow]#{idx} [{tc.attack_category}] {tc.attack_name}[/bold yellow]")
        console.print(f"  [dim]{tc.description}[/dim]")
        console.print(f"  [magenta]Payload:[/magenta] {repr(tc.payload[:80])}...\n")

    if output:
        output.write_text(
            json.dumps([tc.model_dump() for tc in test_cases], indent=2),
            encoding="utf-8",
        )
        console.print(f"[green]Saved attack test suite to {output}[/green]")


def main():
    cli()


if __name__ == "__main__":
    main()
