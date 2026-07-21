"""Finding threshold evaluation."""

from __future__ import annotations

from devops_toolkit.core.models import Finding, ReportStatus, Severity
from devops_toolkit.policies.severities import meets_threshold


def status_for_findings(
    findings: list[Finding],
    threshold: Severity,
    *,
    partial: bool = False,
) -> ReportStatus:
    active = [finding for finding in findings if not finding.suppressed]
    if any(meets_threshold(finding.severity, threshold) for finding in active):
        return ReportStatus.FAIL
    if active or partial:
        return ReportStatus.WARNING
    return ReportStatus.PASS
