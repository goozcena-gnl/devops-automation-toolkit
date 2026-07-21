from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from devops_toolkit.commands import gha_guard, iac_repo_gate, kube_triage, secret_sentinel
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
def test_phase3_python_reports_match_report_contract(
    repository_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(iac_repo_gate, "executable_path", lambda _name: None)
    fixture_collection = json.loads(
        (repository_root / "tests/fixtures/kubernetes/collection.json").read_text(encoding="utf-8")
    )
    monkeypatch.setattr(kube_triage, "resolve_context", lambda _context, _timeout: "development")
    monkeypatch.setattr(
        kube_triage,
        "collect_cluster",
        lambda *_args, **_kwargs: (fixture_collection, {}, False),
    )

    reports = [
        secret_sentinel.build_report(
            repository_root / "tests/fixtures/secret-repo", threshold=Severity.HIGH
        ),
        iac_repo_gate.build_report(
            repository_root / "tests/fixtures/iac-repo",
            threshold=Severity.HIGH,
            run_optional_tools=False,
        ),
        gha_guard.build_report(
            repository_root / "tests/fixtures/gha-repo", threshold=Severity.HIGH
        ),
        kube_triage.build_report(context="development", threshold=Severity.HIGH)[0],
    ]

    validator = _validator(repository_root)
    for report in reports:
        validator.validate(report.as_dict())
