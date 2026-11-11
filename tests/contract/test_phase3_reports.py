from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from devops_toolkit.commands import gha_guard, iac_repo_gate, kube_triage, secret_sentinel
from devops_toolkit.core.models import Severity
from devops_toolkit.core.subprocess import CommandResult
from devops_toolkit.commands.common import exit_code_for_report


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

@pytest.mark.contract
@pytest.mark.parametrize(
    ("scenario", "has_version", "expected_exit"),
    [("complete", True, 0), ("incomplete", False, 5)],
)
def test_iac_versioned_validation_evidence_matches_checked_in_examples(
    repository_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    has_version: bool,
    expected_exit: int,
) -> None:
    (tmp_path / ".terraform").mkdir()
    (tmp_path / ".terraform.lock.hcl").touch()
    (tmp_path / "main.tf").write_text(
        'terraform {\n  required_version = ">= 1.8"\n}\n', encoding="utf-8"
    )
    payload: dict[str, object] = {
        "valid": True,
        "format_version": "1.0",
        "error_count": 0,
        "warning_count": 0,
        "diagnostics": [],
    }
    if not has_version:
        payload.pop("format_version")
    monkeypatch.setattr(iac_repo_gate, "executable_path", lambda _name: "tofu")

    def fake_command(args: list[str], **_kwargs: object) -> CommandResult:
        if args[1] == "fmt":
            return CommandResult(tuple(args), 0, "", "")
        assert args[1:] == ["validate", "-json"]
        return CommandResult(tuple(args), 0, json.dumps(payload), "")

    monkeypatch.setattr(iac_repo_gate, "run_command", fake_command)
    report = iac_repo_gate.build_report(tmp_path, run_optional_tools=False)
    actual = report.as_dict()
    path = repository_root / f"examples/reports/phase3/iac-repo-gate-{scenario}.json"
    expected = json.loads(path.read_text(encoding="utf-8"))
    # Timestamps and temporary directories are not stable example evidence.
    for field in ("started_at", "completed_at", "target"):
        actual["metadata"][field] = expected["metadata"][field]
    _validator(repository_root).validate(actual)
    assert int(exit_code_for_report(report)) == expected_exit
    assert actual == expected
