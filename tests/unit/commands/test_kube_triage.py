from __future__ import annotations

import json
import zipfile

from devops_toolkit.commands.kube_triage import (
    analyze_collection,
    sanitize_kubernetes_payload,
    write_sanitized_bundle,
)
from devops_toolkit.core.models import Report, ReportMetadata, ReportStatus, utc_now


def _collection(repository_root):
    return json.loads(
        (repository_root / "tests/fixtures/kubernetes/collection.json").read_text(encoding="utf-8")
    )


def test_kube_analysis_detects_node_and_pod_failures(repository_root) -> None:
    findings = analyze_collection(_collection(repository_root))
    identifiers = {finding.id for finding in findings}
    assert "KUBE-NODE-NOT-READY" in identifiers
    assert "KUBE-POD-PENDING" in identifiers
    assert "KUBE-CONTAINER-WAITING" in identifiers
    assert "KUBE-CONTAINER-RESTARTS" in identifiers


def test_kubernetes_sanitizer_redacts_environment_values(repository_root) -> None:
    sanitized = sanitize_kubernetes_payload(_collection(repository_root))
    serialized = json.dumps(sanitized)
    assert "super-secret-value" not in serialized
    assert "[REDACTED]" in serialized


def test_sanitized_bundle_contains_no_environment_secret(repository_root, tmp_path) -> None:
    now = utc_now()
    report = Report(
        metadata=ReportMetadata(
            tool="kube-triage",
            tool_version="0.3.0",
            started_at=now,
            completed_at=now,
            target="test",
        ),
        status=ReportStatus.PASS,
    )
    output = tmp_path / "bundle.zip"
    write_sanitized_bundle(output, report, _collection(repository_root))
    with zipfile.ZipFile(output) as archive:
        content = "".join(archive.read(name).decode() for name in archive.namelist())
    assert "super-secret-value" not in content
    assert "[REDACTED]" in content
