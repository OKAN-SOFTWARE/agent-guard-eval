"""Console reporter with rich terminal styling."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentguard.models import EvaluationResult, Severity


def render_console_report(result: EvaluationResult, console: Console = None) -> str:
    """Renders evaluation results to terminal format and returns string output."""
    capture_console = Console(record=True, width=100) if console is None else console

    status_color = "green" if result.passed else "red"
    status_text = (
        "[bold green]PASSED[/bold green]"
        if result.passed
        else "[bold red]FAILED[/bold red]"
    )

    summary_panel = Panel(
        Text.from_markup(
            f"Session: [bold cyan]{result.session_id}[/bold cyan] | "
            f"Status: {status_text} | "
            f"Checks: {result.passed_checks}/{result.total_checks} passed | "
            f"Duration: [yellow]{result.duration_ms}ms[/yellow]"
        ),
        title="[bold]AgentGuard Evaluation Summary[/bold]",
        border_style=status_color,
    )
    capture_console.print(summary_panel)

    if not result.findings:
        capture_console.print(
            "[green]✔ No security, schema, or execution loop anomalies detected.[/green]\n"
        )
        return capture_console.export_text() if console is None else ""

    table = Table(
        title=f"Findings ({len(result.findings)} issues detected)",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Severity", width=12)
    table.add_column("Rule ID", width=12)
    table.add_column("Step", width=6)
    table.add_column("Tool", width=15)
    table.add_column("Description", width=45)

    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
    }

    for finding in result.findings:
        color = severity_colors.get(finding.severity, "white")
        step_str = str(finding.step_id) if finding.step_id is not None else "-"
        tool_str = finding.tool_name or "-"
        table.add_row(
            Text(finding.severity.value, style=color),
            finding.rule_id,
            step_str,
            tool_str,
            finding.message,
        )

    capture_console.print(table)
    capture_console.print()

    return capture_console.export_text() if console is None else ""
