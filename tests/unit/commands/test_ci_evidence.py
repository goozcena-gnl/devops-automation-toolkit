from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.ci_evidence import analyze_logs, build_report, write_bundle
from devops_toolkit.core.models import Severity


def test_ci_log_analysis_deduplicates_and_classifies() -> None:
    findings, counts, timeline = analyze_logs(
        {"job.log": "tests failed\ntests failed\nexit code 137"}
    )
    assert {finding.id for finding in findings} == {"CI-TEST-FAILURE", "CI-OUT-OF-MEMORY"}
    assert counts["CI-TEST-FAILURE"] == 2
    assert timeline


def test_ci_evidence_redacts_bundle(repository_root: Path, tmp_path: Path) -> None:
    fixture = repository_root / "tests/fixtures/ci-logs"
    report, logs, metadata = build_report(
        logs_dir=fixture,
        metadata_path=fixture / "metadata.json",
        threshold=Severity.HIGH,
    )
    assert report.status.value == "fail"
    assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in "\n".join(logs.values())
    bundle = tmp_path / "ci-evidence.zip"
    write_bundle(bundle, report, logs, metadata)
    assert bundle.exists()
