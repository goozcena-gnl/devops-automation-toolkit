"""Report format dispatcher."""

from __future__ import annotations

from enum import StrEnum

from devops_toolkit.core.models import Report
from devops_toolkit.reporters.console import render_console
from devops_toolkit.reporters.json_report import render_json
from devops_toolkit.reporters.markdown import render_markdown
from devops_toolkit.reporters.sarif import render_sarif


class ReportFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


def render_report(report: Report, report_format: ReportFormat, *, color: bool = True) -> str:
    if report_format is ReportFormat.CONSOLE:
        return render_console(report, color=color)
    if report_format is ReportFormat.JSON:
        return render_json(report)
    if report_format is ReportFormat.MARKDOWN:
        return render_markdown(report)
    if report_format is ReportFormat.SARIF:
        return render_sarif(report)
    raise ValueError(f"Unsupported report format: {report_format}")
