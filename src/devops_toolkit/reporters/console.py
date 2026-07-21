"""Rich console reporter."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.table import Table

from devops_toolkit.core.models import Report


def render_console(report: Report, *, color: bool = True) -> str:
    buffer = StringIO()
    console = Console(
        file=buffer,
        force_terminal=color,
        color_system="standard" if color else None,
        width=160,
    )
    console.print(f"[bold]{report.metadata.tool}[/bold] target={report.metadata.target}")
    console.print(f"status={report.status.value} partial={report.metadata.partial}")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Finding")
    table.add_column("Resource")
    for finding in report.findings:
        resource = ""
        if finding.resource:
            resource = f"{finding.resource.type}/{finding.resource.name}"
        suffix = " [suppressed]" if finding.suppressed else ""
        table.add_row(
            finding.severity.value,
            finding.confidence.value,
            finding.title + suffix,
            resource,
        )
    if report.findings:
        console.print(table)
    else:
        console.print("No findings.")
    return buffer.getvalue()
