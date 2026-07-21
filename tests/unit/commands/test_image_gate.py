from __future__ import annotations

from pathlib import Path

import pytest

from devops_toolkit.commands.image_gate import analyze_trivy, build_report, load_trivy_json
from devops_toolkit.core.exceptions import ConfigurationError
from devops_toolkit.core.models import Severity


def test_image_gate_normalizes_findings_without_raw_secret(repository_root: Path) -> None:
    path = repository_root / "tests/fixtures/image/trivy.json"
    payload = load_trivy_json(path)
    findings, metrics = analyze_trivy(payload, "example.invalid/app:1.0")
    assert metrics["vulnerabilities"] == 1
    assert metrics["secrets"] == 1
    serialized = "\n".join(finding.model_dump_json() for finding in findings)
    assert "SYNTHETIC_SECRET_VALUE_MUST_NOT_APPEAR" not in serialized
    assert {finding.id for finding in findings} == {"IMAGE-VULNERABILITY", "IMAGE-EMBEDDED-SECRET"}


def test_image_gate_fixture_report_fails(repository_root: Path) -> None:
    report = build_report(
        "example.invalid/app:1.0",
        trivy_json=repository_root / "tests/fixtures/image/trivy.json",
        threshold=Severity.HIGH,
    )
    assert report.status.value == "fail"


def test_offline_scan_refuses_to_fabricate_sbom(repository_root: Path, tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="cannot be used to reconstruct"):
        build_report(
            "example.invalid/app:1.0",
            trivy_json=repository_root / "tests/fixtures/image/trivy.json",
            sbom_output=tmp_path / "sbom.json",
        )
