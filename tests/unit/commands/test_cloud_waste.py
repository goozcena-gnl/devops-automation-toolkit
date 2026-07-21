from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.cloud_waste import build_report
from devops_toolkit.core.models import ReportStatus, Severity


def test_cloud_waste_snapshot_detects_orphans_idle_compute_and_tags(repository_root: Path) -> None:
    report = build_report(
        provider="aws",
        snapshot_path=repository_root / "tests/fixtures/cloud/aws-waste-risky.json",
        threshold=Severity.HIGH,
        required_tags={"owner", "environment", "cost-center"},
    )
    identifiers = {finding.id for finding in report.findings}
    assert "CLOUD-WASTE-UNATTACHED-STORAGE" in identifiers
    assert "CLOUD-WASTE-IDLE-COMPUTE" in identifiers
    assert "CLOUD-WASTE-MISSING-REQUIRED-TAGS" in identifiers
    assert report.extensions["destructive_actions_available"] is False
    assert report.status is ReportStatus.FAIL
