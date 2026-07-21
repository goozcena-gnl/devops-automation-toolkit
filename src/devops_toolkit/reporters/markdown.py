"""Markdown reporter."""

from __future__ import annotations

from devops_toolkit.core.models import Report


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report) -> str:
    lines = [
        f"# {report.metadata.tool} report",
        "",
        f"- **Target:** `{report.metadata.target}`",
        f"- **Status:** `{report.status.value}`",
        f"- **Started:** {report.metadata.started_at.isoformat()}",
        f"- **Completed:** {report.metadata.completed_at.isoformat()}",
        f"- **Partial:** {'yes' if report.metadata.partial else 'no'}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for key, count in report.summary.items():
        lines.append(f"| {key} | {count} |")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings.")
    else:
        lines.extend(
            [
                "| Severity | Confidence | Finding | Resource | Recommendation |",
                "|---|---|---|---|---|",
            ]
        )
        for finding in report.findings:
            resource = ""
            if finding.resource:
                resource = f"{finding.resource.type}/{finding.resource.name}"
            title = f"~~{finding.title}~~" if finding.suppressed else finding.title
            lines.append(
                "| "
                + " | ".join(
                    [
                        finding.severity.value,
                        finding.confidence.value,
                        _escape(title),
                        _escape(resource),
                        _escape(finding.recommendation),
                    ]
                )
                + " |"
            )
    return "\n".join(lines) + "\n"
