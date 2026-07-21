from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.repo_baseline import build_report, load_snapshot
from devops_toolkit.core.models import ReportStatus, Severity


def test_repository_snapshot_detects_governance_gaps(repository_root: Path) -> None:
    snapshot_path = repository_root / "tests/fixtures/github/insecure-repository.json"
    report = build_report(snapshot_path=snapshot_path, threshold=Severity.HIGH)
    identifiers = {finding.id for finding in report.findings}
    assert "GITHUB-FORCE-PUSH-ALLOWED" in identifiers
    assert "GITHUB-ACTIONS-DEFAULT-WRITE" in identifiers
    assert "GITHUB-SECURITY-POLICY-MISSING" in identifiers
    assert report.status is ReportStatus.FAIL


def test_load_snapshot_requires_mapping(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.json"
    path.write_text("[]", encoding="utf-8")
    try:
        load_snapshot(path)
    except Exception as exc:
        assert "root must be an object" in str(exc)
    else:
        raise AssertionError("expected invalid snapshot to fail")
