from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.kube_rightsize import (
    analyze_snapshot,
    build_report,
    parse_cpu,
    parse_memory,
)
from devops_toolkit.core.models import Severity


def test_quantity_parsing() -> None:
    assert parse_cpu("250m") == 0.25
    assert parse_cpu("1") == 1.0
    assert parse_memory("1Gi") == 1024**3
    assert parse_memory("500Mi") == 500 * 1024**2


def test_rightsize_snapshot_detects_requests_and_memory_risk(repository_root: Path) -> None:
    report = build_report(
        snapshot_path=repository_root / "tests/fixtures/kubernetes-rightsize/snapshot.json",
        threshold=Severity.HIGH,
        include_patch_preview=True,
    )
    identifiers = {finding.id for finding in report.findings}
    assert "KUBE-MEMORY-LIMIT-RISK" in identifiers
    assert "KUBE-RESOURCES-MISSING-REQUEST" in identifiers
    assert "KUBE-CPU-OVERREQUESTED" in identifiers
    assert report.extensions["patch_preview"]


def test_empty_snapshot_marks_missing_metrics() -> None:
    findings, previews, counters = analyze_snapshot({"pods": {}, "metrics": {}})
    assert findings == [] and previews == [] and counters == {}
