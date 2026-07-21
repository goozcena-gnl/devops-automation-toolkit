from datetime import UTC, datetime, timedelta

from devops_toolkit.core.models import Confidence, Finding, ReportStatus, Severity
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.policies.exceptions import PolicyException, apply_exceptions


def make_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id="TEST-POLICY",
        tool="test",
        category="test",
        severity=severity,
        confidence=Confidence.HIGH,
        title="Policy test",
    )


def test_threshold_failure() -> None:
    assert status_for_findings([make_finding()], Severity.HIGH) is ReportStatus.FAIL


def test_lower_findings_generate_warning() -> None:
    assert status_for_findings([make_finding(Severity.LOW)], Severity.HIGH) is ReportStatus.WARNING


def test_active_exception_suppresses_finding() -> None:
    finding = make_finding()
    exception = PolicyException(
        fingerprint=finding.fingerprint,
        justification="Reviewed synthetic finding",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    result = apply_exceptions([finding], [exception])
    assert result[0].suppressed is True
    assert status_for_findings(result, Severity.HIGH) is ReportStatus.PASS


def test_expired_exception_does_not_suppress() -> None:
    finding = make_finding()
    exception = PolicyException(
        fingerprint=finding.fingerprint,
        justification="Expired synthetic exception",
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    result = apply_exceptions([finding], [exception])
    assert result[0].suppressed is False
