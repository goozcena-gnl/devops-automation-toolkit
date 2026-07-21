from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.budget_guard import build_report
from devops_toolkit.core.models import ReportStatus, Severity


def test_budget_snapshot_detects_overspend_alert_gaps_and_anomaly(repository_root: Path) -> None:
    report = build_report(
        provider="aws",
        snapshot_path=repository_root / "tests/fixtures/cloud/aws-budget-risky.json",
        threshold=Severity.HIGH,
    )
    identifiers = {finding.id for finding in report.findings}
    assert "CLOUD-BUDGET-EXCEEDED" in identifiers
    assert "CLOUD-BUDGET-FORECAST-OVERSPEND" in identifiers
    assert "CLOUD-BUDGET-MISSING-THRESHOLDS" in identifiers
    assert "CLOUD-COST-RAPID-INCREASE" in identifiers
    assert report.status is ReportStatus.FAIL
