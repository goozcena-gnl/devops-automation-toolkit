from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from devops_toolkit.commands import kubeconfig_hygiene, plan_risk, repo_baseline, tls_audit
from devops_toolkit.core.models import Severity


def _validator(repository_root: Path) -> Draft202012Validator:
    schema_dir = repository_root / "configs/schemas"
    report_schema = json.loads((schema_dir / "report.schema.json").read_text(encoding="utf-8"))
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text(encoding="utf-8"))
    resource = Resource.from_contents(finding_schema)
    registry = (
        Registry()
        .with_resource("finding.schema.json", resource)
        .with_resource(finding_schema["$id"], resource)
    )
    return Draft202012Validator(report_schema, registry=registry)


@pytest.mark.contract
def test_phase4_python_reports_match_contract(
    repository_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text(
        """apiVersion: v1
kind: Config
clusters: []
users: []
contexts: []
current-context: ""
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        tls_audit,
        "inspect_endpoint",
        lambda *_args, **_kwargs: {
            "endpoint": "example.test:443",
            "verified": True,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate": {"notAfter": "Jan  1 00:00:00 2035 GMT"},
            "fingerprint": "sha256:fixture",
        },
    )
    reports = [
        plan_risk.build_report(
            repository_root / "tests/fixtures/terraform-plan/risky.json", threshold=Severity.HIGH
        ),
        repo_baseline.build_report(
            snapshot_path=repository_root / "tests/fixtures/github/insecure-repository.json",
            threshold=Severity.HIGH,
        ),
        kubeconfig_hygiene.build_report([kubeconfig], threshold=Severity.HIGH),
        tls_audit.build_report([tls_audit.Endpoint("example.test")], threshold=Severity.HIGH),
    ]
    validator = _validator(repository_root)
    for report in reports:
        validator.validate(report.as_dict())
