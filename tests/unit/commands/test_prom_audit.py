from __future__ import annotations

from pathlib import Path

import pytest

from devops_toolkit.commands.prom_audit import (
    analyze_rules,
    analyze_targets,
    build_report,
    collect_snapshot,
)
from devops_toolkit.core.exceptions import ConfigurationError
from devops_toolkit.core.models import Severity


def test_prometheus_target_and_rule_analysis(repository_root: Path) -> None:
    report = build_report(
        snapshot_path=repository_root / "tests/fixtures/prometheus/snapshot.json",
        expected_jobs={"api", "node", "missing"},
        threshold=Severity.HIGH,
    )
    identifiers = {finding.id for finding in report.findings}
    assert "PROM-TARGET-DOWN" in identifiers
    assert "PROM-SCRAPE-NEAR-TIMEOUT" in identifiers
    assert "PROM-EXPECTED-JOB-ABSENT" in identifiers
    assert "PROM-RULE-UNHEALTHY" in identifiers
    assert report.status.value == "fail"


def test_empty_prometheus_payloads_are_safe() -> None:
    target_findings, target_metrics = analyze_targets(
        {}, duration_ratio_threshold=0.8, expected_jobs=set()
    )
    rule_findings, rule_metrics = analyze_rules({})
    assert target_findings == [] and rule_findings == []
    assert target_metrics["active"] == 0 and rule_metrics["rules"] == 0


def test_prometheus_rejects_non_http_url() -> None:
    with pytest.raises(ConfigurationError, match="HTTP or HTTPS"):
        collect_snapshot(
            "file:///tmp/prometheus",
            timeout_seconds=1,
            bearer_token=None,
            ca_file=None,
        )
