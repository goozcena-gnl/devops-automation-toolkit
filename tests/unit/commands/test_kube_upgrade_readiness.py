from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.kube_upgrade_readiness import build_report
from devops_toolkit.core.models import ReportStatus, Severity


def test_upgrade_snapshot_detects_version_api_node_and_drain_blockers(
    repository_root: Path,
) -> None:
    report = build_report(
        target_version="1.33.0",
        snapshot_path=repository_root / "tests/fixtures/kubernetes-upgrade/snapshot.json",
        threshold=Severity.HIGH,
    )
    identifiers = {finding.id for finding in report.findings}
    assert "KUBE-UPGRADE-MINOR-SKIP" in identifiers
    assert "KUBE-UPGRADE-REMOVED-API-USAGE" in identifiers
    assert "KUBE-UPGRADE-NODE-NOT-READY" in identifiers
    assert "KUBE-UPGRADE-PDB-BLOCKS-DISRUPTION" in identifiers
    assert "KUBE-UPGRADE-CRD-STORAGE-VERSION" in identifiers
    assert report.extensions["cluster_changes_executed"] is False
    assert report.status is ReportStatus.FAIL
