"""Severity comparison helpers."""

from devops_toolkit.core.models import SEVERITY_RANK, Severity


def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]
