from devops_toolkit.core.models import Confidence, Finding, Severity


def test_finding_generates_stable_fingerprint() -> None:
    finding = Finding(
        id="TEST-001",
        tool="test",
        category="quality",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        title="Example",
    )
    assert finding.fingerprint.startswith("sha256:")
    assert len(finding.fingerprint) == 71
