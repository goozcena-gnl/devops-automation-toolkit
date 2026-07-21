from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.iac_drift_guard import build_report
from devops_toolkit.core.models import ReportStatus, Severity


def test_drift_plan_detects_updates_deletion_and_failed_checks(repository_root: Path) -> None:
    report = build_report(
        repository_root,
        plan_json=repository_root / "tests/fixtures/terraform-drift/drift.json",
        threshold=Severity.HIGH,
    )
    identifiers = {finding.id for finding in report.findings}
    assert "IAC-DRIFT-EXTERNAL-UPDATE" in identifiers
    assert "IAC-DRIFT-REMOTE-DELETION" in identifiers
    assert "IAC-DRIFT-CHECKS-FAILED" in identifiers
    assert report.extensions["apply_executed"] is False
    assert report.status is ReportStatus.FAIL
