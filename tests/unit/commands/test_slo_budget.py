from __future__ import annotations

from pathlib import Path

from devops_toolkit.commands.slo_budget import (
    BurnWindow,
    Sample,
    analyze_slo,
    build_report,
    load_samples,
)
from devops_toolkit.core.models import Severity


def test_slo_calculation_detects_exhausted_budget(repository_root: Path) -> None:
    report = build_report(repository_root / "tests/fixtures/slo/spec.yaml")
    identifiers = {finding.id for finding in report.findings}
    assert "SLO-OBJECTIVE-MISSED" in identifiers
    assert "SLO-ERROR-BUDGET-EXHAUSTED" in identifiers
    assert "SLO-BURN-RATE-EXCEEDED" in identifiers
    assert report.extensions["slo"]["compliance"] == 0.98


def test_slo_no_data_is_distinct() -> None:
    findings, metrics = analyze_slo(
        "empty",
        0.99,
        [Sample(1.0, 0.0, 0.0)],
        [BurnWindow("fast", 1, 10.0, Severity.CRITICAL)],
    )
    assert findings[0].id == "SLO-NO-DATA"
    assert metrics["compliance"] is None


def test_load_csv_samples(repository_root: Path) -> None:
    samples = load_samples(repository_root / "tests/fixtures/slo/samples.csv")
    assert len(samples) == 3
    assert sum(item.total for item in samples) == 3000
