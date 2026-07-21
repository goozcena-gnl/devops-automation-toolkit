"""Shared command orchestration helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer

from devops_toolkit.core.config import load_config
from devops_toolkit.core.exit_codes import ExitCode
from devops_toolkit.core.filesystem import atomic_write_text
from devops_toolkit.core.models import Report, ReportStatus, Severity
from devops_toolkit.reporters.dispatcher import ReportFormat, render_report


def tool_config(config_paths: list[Path], tool_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return merged global configuration and a tool-specific mapping."""

    config = load_config(config_paths)
    raw_tool = config.get("tools", {}).get(tool_name, {})
    return config, raw_tool if isinstance(raw_tool, dict) else {}


def severity_from_config(config: dict[str, Any], override: Severity | None) -> Severity:
    if override is not None:
        return override
    value = str(config["defaults"]["severity_threshold"])
    return Severity(value)


def timeout_from_config(config: dict[str, Any], override: int | None) -> int:
    if override is not None:
        return override
    return int(config["defaults"]["timeout_seconds"])


def format_from_config(config: dict[str, Any], override: ReportFormat | None) -> ReportFormat:
    if override is not None:
        return override
    return ReportFormat(str(config["defaults"]["format"]))


def no_color_from_config(config: dict[str, Any], override: bool | None) -> bool:
    if override is not None:
        return override
    return bool(config["defaults"]["no_color"])


def emit_report(
    report: Report,
    report_format: ReportFormat,
    output: Path | None,
    *,
    no_color: bool = False,
) -> None:
    rendered = render_report(report, report_format, color=not no_color)
    if output is not None:
        atomic_write_text(output, rendered)
        typer.echo(str(output))
    else:
        typer.echo(rendered, nl=False)


def exit_code_for_report(report: Report) -> ExitCode:
    if report.status is ReportStatus.FAIL:
        return ExitCode.FINDINGS_EXCEEDED_THRESHOLD
    if report.status is ReportStatus.ERROR:
        return ExitCode.INTERNAL_ERROR
    if report.status is ReportStatus.BLOCKED:
        return ExitCode.SAFETY_BLOCKED
    if report.metadata.partial:
        return ExitCode.PARTIAL_COLLECTION
    return ExitCode.SUCCESS
