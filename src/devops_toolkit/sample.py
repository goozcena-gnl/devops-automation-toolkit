"""Synthetic report used to validate output contracts."""

from devops_toolkit.core.models import (
    Confidence,
    Evidence,
    Finding,
    Report,
    ReportMetadata,
    ResourceRef,
    Severity,
    utc_now,
)
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__


def build_sample_report() -> Report:
    started = utc_now()
    finding = Finding(
        id="FOUNDATION-EXAMPLE",
        tool="devops-toolkit",
        category="foundation",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Synthetic foundation finding",
        description="Used to verify output contracts without external infrastructure.",
        recommendation="Replace the synthetic collector during the relevant implementation phase.",
        resource=ResourceRef(type="Repository", name="devops-automation-toolkit"),
        evidence=Evidence(summary="A deterministic synthetic fixture was loaded"),
    )
    completed = utc_now()
    findings = [finding]
    return Report(
        metadata=ReportMetadata(
            tool="devops-toolkit",
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target="local-foundation",
            capabilities=["json", "markdown", "sarif", "redaction", "safe-subprocess"],
        ),
        findings=findings,
        status=status_for_findings(findings, Severity.HIGH),
    )
