from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from devops_toolkit.commands import (
    budget_guard,
    cloud_iam_audit,
    cloud_waste,
    iac_drift_guard,
    kube_upgrade_readiness,
)
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


def test_phase6_reports_match_contract(repository_root: Path) -> None:
    reports = [
        cloud_iam_audit.build_report(
            provider="azure",
            snapshot_path=repository_root / "tests/fixtures/cloud/azure-iam-risky.json",
            threshold=Severity.HIGH,
        ),
        cloud_waste.build_report(
            provider="aws",
            snapshot_path=repository_root / "tests/fixtures/cloud/aws-waste-risky.json",
            threshold=Severity.HIGH,
            required_tags={"owner", "environment", "cost-center"},
        ),
        budget_guard.build_report(
            provider="aws",
            snapshot_path=repository_root / "tests/fixtures/cloud/aws-budget-risky.json",
            threshold=Severity.HIGH,
        ),
        iac_drift_guard.build_report(
            repository_root,
            plan_json=repository_root / "tests/fixtures/terraform-drift/drift.json",
            threshold=Severity.HIGH,
        ),
        kube_upgrade_readiness.build_report(
            target_version="1.33.0",
            snapshot_path=repository_root / "tests/fixtures/kubernetes-upgrade/snapshot.json",
            threshold=Severity.HIGH,
        ),
    ]
    validator = _validator(repository_root)
    for report in reports:
        validator.validate(report.as_dict())
