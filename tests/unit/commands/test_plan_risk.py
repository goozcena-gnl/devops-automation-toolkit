from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.plan_risk import build_report, load_plan
from devops_toolkit.core.models import ReportStatus, Severity


def test_risky_plan_detects_destructive_and_security_changes(repository_root: Path) -> None:
    plan = repository_root / "tests/fixtures/terraform-plan/risky.json"
    report = build_report(plan, threshold=Severity.HIGH)
    identifiers = {finding.id for finding in report.findings}
    assert "TFPLAN-RESOURCE-REPLACEMENT" in identifiers
    assert "TFPLAN-PUBLIC-EXPOSURE" in identifiers
    assert "TFPLAN-IAM-WILDCARD" in identifiers
    assert "TFPLAN-ENCRYPTION-DISABLED" in identifiers
    assert "TFPLAN-RETENTION-REDUCED" in identifiers
    assert report.status is ReportStatus.FAIL


def test_load_plan_rejects_non_plan_json(tmp_path: Path) -> None:
    path = tmp_path / "not-plan.json"
    path.write_text("{}", encoding="utf-8")
    try:
        load_plan(path)
    except Exception as exc:
        assert "resource_changes" in str(exc)
    else:
        raise AssertionError("expected invalid plan to fail")
