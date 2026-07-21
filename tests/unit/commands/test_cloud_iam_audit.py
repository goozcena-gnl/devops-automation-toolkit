from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.cloud_iam_audit import build_report
from devops_toolkit.core.models import ReportStatus, Severity


def test_azure_snapshot_detects_broad_roles_and_expired_credentials(repository_root: Path) -> None:
    report = build_report(
        provider="azure",
        snapshot_path=repository_root / "tests/fixtures/cloud/azure-iam-risky.json",
        threshold=Severity.HIGH,
    )
    identifiers = {finding.id for finding in report.findings}
    assert "AZURE-IAM-BROAD-PRIVILEGED-ROLE" in identifiers
    assert "AZURE-IAM-CUSTOM-ROLE-WILDCARD" in identifiers
    assert "AZURE-IAM-EXPIRED-CREDENTIAL" in identifiers
    assert report.status is ReportStatus.FAIL
