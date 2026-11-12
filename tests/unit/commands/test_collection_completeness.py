from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devops_toolkit.cli import app
from devops_toolkit.commands import iac_repo_gate, secret_sentinel
from devops_toolkit.core.subprocess import CommandResult
from devops_toolkit.reporters.dispatcher import ReportFormat, render_report


def test_secret_complete_empty_and_intentional_exclusion(tmp_path: Path) -> None:
    empty = secret_sentinel.build_report(tmp_path)
    assert empty.status == "pass"
    assert not empty.metadata.partial
    assert empty.extensions["collection"]["working_tree"] == "complete"
    assert empty.extensions["collection"]["git_history"] == "not_requested"
    excluded = tmp_path / "generated"
    excluded.mkdir()
    (excluded / "ignored.txt").write_text("synthetic", encoding="utf-8")
    report = secret_sentinel.build_report(tmp_path, excluded_dirs={"generated"})
    assert report.status == "pass"
    assert not report.findings
    assert not report.metadata.partial
    assert report.extensions["collection"]["working_tree"] == "intentionally_excluded"
    assert report.extensions["metrics"]["directories_excluded"] == 1


def test_secret_size_limit_changes_cli_exit(tmp_path: Path) -> None:
    (tmp_path / "large.txt").write_bytes(b"x" * 1025)
    result = CliRunner().invoke(
        app,
        ["secret-sentinel", str(tmp_path), "--max-file-bytes", "1024", "--format", "json"],
    )
    assert result.exit_code == 5, result.output
    report = json.loads(result.stdout)
    assert report["status"] == "warning"
    assert report["metadata"]["partial"]
    assert report["extensions"]["collection"]["working_tree"] == "failed"
    assert report["extensions"]["metrics"]["files_oversized"] == 1
    assert report["extensions"]["metrics"]["files_scanned"] == 0

    (tmp_path / "small.txt").write_text("synthetic", encoding="utf-8")
    mixed = secret_sentinel.build_report(tmp_path, max_file_bytes=1024)
    assert mixed.extensions["collection"]["working_tree"] == "partial"
    assert mixed.metadata.partial
    assert mixed.extensions["metrics"]["files_scanned"] == 1


@pytest.mark.parametrize("truncated", [False, True])
def test_requested_git_history_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, truncated: bool
) -> None:
    (tmp_path / ".git").mkdir()

    def git(args: list[str], **kwargs: object) -> CommandResult:
        if args[1] == "ls-files":
            return CommandResult(tuple(args), 0, "", "")
        assert args[1] == "rev-list"
        return CommandResult(tuple(args), 0 if truncated else 1, "", "", truncated=truncated)

    monkeypatch.setattr(secret_sentinel, "run_command", git)
    result = CliRunner().invoke(
        app, ["secret-sentinel", str(tmp_path), "--history", "--format", "json"]
    )
    assert result.exit_code == 5, result.output
    report = json.loads(result.stdout)
    assert report["extensions"]["collection"]["git_history"] == "failed"
    assert report["extensions"]["metrics"]["commits_scanned"] == 0
    assert report["metadata"]["partial"]


@pytest.fixture
def terraform_project(tmp_path: Path) -> Path:
    (tmp_path / ".terraform").mkdir()
    (tmp_path / "main.tf").write_text(
        'terraform {\n  required_version = ">= 1.8"\n}\n', encoding="utf-8"
    )
    (tmp_path / ".terraform.lock.hcl").touch()
    return tmp_path


def _validator(monkeypatch: pytest.MonkeyPatch, result: CommandResult) -> None:
    monkeypatch.setattr(iac_repo_gate, "executable_path", lambda name: name)

    def run(args: list[str], **kwargs: object) -> CommandResult:
        assert args[0] == "tofu"
        if args[1] == "fmt":
            return CommandResult(tuple(args), 0, "", "")
        assert args[1:] == ["validate", "-json"]
        return result

    monkeypatch.setattr(iac_repo_gate, "run_command", run)


def _validation_json(**overrides: object) -> str:
    payload: dict[str, object] = {
        "format_version": "1.0",
        "valid": True,
        "error_count": 0,
        "warning_count": 0,
        "diagnostics": [],
    }
    payload.update(overrides)
    return json.dumps(payload)


@pytest.mark.parametrize(
    ("returncode", "stdout", "timed_out", "truncated", "state"),
    [
        (1, "", False, False, "failed"),
        (0, "", False, False, "failed"),
        (0, "{", False, False, "failed"),
        (0, "{}", False, False, "failed"),
        (0, _validation_json(diagnostics=[None]), False, False, "failed"),
        (0, _validation_json(), False, True, "partial"),
        (124, "", True, False, "partial"),
        (0, _validation_json(), False, False, "complete"),
    ],
)
def test_terraform_requires_successful_structured_validation(
    terraform_project: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stdout: str,
    timed_out: bool,
    truncated: bool,
    state: str,
) -> None:
    _validator(monkeypatch, CommandResult((), returncode, stdout, "", timed_out, truncated))
    result = CliRunner().invoke(
        app, ["iac-repo-gate", str(terraform_project), "--no-optional-tools", "--format", "json"]
    )
    complete = state == "complete"
    assert result.exit_code == (0 if complete else 5), result.output
    report = json.loads(result.stdout)
    assert report["metadata"]["partial"] is not complete
    assert report["extensions"]["tools"]["tofu"]["validated"] is complete
    assert report["extensions"]["tools"]["tofu"]["validation_state"] == state


def test_terraform_unavailable_is_incomplete(
    terraform_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(iac_repo_gate, "executable_path", lambda name: None)
    report = iac_repo_gate.build_report(terraform_project, run_optional_tools=False)
    assert report.metadata.partial
    assert report.extensions["tools"]["terraform-opentofu"]["available"] is False
    assert report.extensions["tools"]["terraform-opentofu"]["validation_state"] == "failed"


def test_terraform_diagnostic_retains_finding_without_secret(
    terraform_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "ghp_" + "A1SyntheticCanary123456789012"
    diagnostic = {
        "severity": "error",
        "summary": f"Invalid argument {canary}",
        "detail": f"Unexpected value {canary}",
        "range": {"filename": "main.tf", "start": {"line": 1}},
    }
    payload = _validation_json(valid=False, error_count=1, diagnostics=[diagnostic])
    _validator(monkeypatch, CommandResult((), 1, payload, canary))
    report = iac_repo_gate.build_report(terraform_project, run_optional_tools=False)
    assert report.status == "fail"
    assert not report.metadata.partial
    assert not report.extensions["tools"]["tofu"]["validated"]
    assert report.extensions["tools"]["tofu"]["validation_state"] == "complete"
    assert report.extensions["tools"]["tofu"]["validation_reason"] == "rejected"
    result = CliRunner().invoke(
        app, ["iac-repo-gate", str(terraform_project), "--no-optional-tools", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    cli_report = json.loads(result.stdout)
    assert cli_report["metadata"]["partial"] is False
    assert cli_report["extensions"]["tools"]["tofu"]["validation_state"] == "complete"
    assert cli_report["extensions"]["tools"]["tofu"]["validated"] is False
    (finding,) = report.findings
    assert finding.id == "IAC-TF-VALIDATE"
    assert finding.evidence.location == "main.tf"
    assert finding.evidence.line == 1
    assert "Invalid argument" in finding.title
    for fmt in ReportFormat:
        assert canary not in render_report(report, fmt, color=False)


@pytest.mark.parametrize(
    ("returncode", "valid", "error_count"),
    [(0, False, 1), (1, True, 0)],
)
def test_terraform_inconsistent_structured_result_remains_incomplete(
    terraform_project: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    valid: bool,
    error_count: int,
) -> None:
    diagnostics = (
        [{"severity": "error", "summary": "Synthetic validation error"}] if error_count else []
    )
    payload = _validation_json(valid=valid, error_count=error_count, diagnostics=diagnostics)
    _validator(monkeypatch, CommandResult((), returncode, payload, ""))
    report = iac_repo_gate.build_report(terraform_project, run_optional_tools=False)
    assert report.metadata.partial
    assert not report.extensions["tools"]["tofu"]["validated"]
    assert report.extensions["tools"]["tofu"]["validation_state"] == "failed"
    assert report.extensions["tools"]["tofu"]["validation_reason"] == "inconsistent_result"
    assert report.status == ("fail" if error_count else "warning")


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"format_version": None}, "invalid_format_version"),
        ({"format_version": "1.invalid"}, "invalid_format_version"),
        ({"format_version": "2.0"}, "unsupported_format_version"),
        ({"error_count": None}, "invalid_error_count"),
        ({"error_count": -1}, "invalid_error_count"),
        ({"error_count": True}, "invalid_error_count"),
        ({"error_count": 1}, "invalid_error_count"),
        ({"warning_count": None}, "invalid_warning_count"),
        ({"warning_count": -1}, "invalid_warning_count"),
        ({"warning_count": True}, "invalid_warning_count"),
        ({"warning_count": 1}, "invalid_warning_count"),
        ({"valid": False}, "invalid_validity"),
    ],
)
def test_terraform_rejects_inconsistent_validation_contract(
    terraform_project: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    reason: str,
) -> None:
    _validator(monkeypatch, CommandResult((), 0, _validation_json(**overrides), ""))
    result = CliRunner().invoke(
        app, ["iac-repo-gate", str(terraform_project), "--no-optional-tools", "--format", "json"]
    )
    assert result.exit_code == 5, result.output
    report = json.loads(result.stdout)
    assert report["metadata"]["partial"] is True
    metadata = report["extensions"]["tools"]["tofu"]
    assert metadata["validated"] is False
    assert metadata["validation_state"] == "failed"
    assert metadata["validation_reason"] == reason


@pytest.mark.parametrize("field", ["format_version", "error_count", "warning_count"])
def test_terraform_requires_version_and_counters(
    terraform_project: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    payload = json.loads(_validation_json())
    payload.pop(field)
    _validator(monkeypatch, CommandResult((), 0, json.dumps(payload), ""))
    report = iac_repo_gate.build_report(terraform_project, run_optional_tools=False)
    assert report.metadata.partial is True
    assert report.status == "warning"
    metadata = report.extensions["tools"]["tofu"]
    assert metadata["validated"] is False
    assert metadata["validation_reason"] == f"invalid_{field}"


@pytest.mark.parametrize("version", ["1.0", "1.1", "1.25"])
def test_terraform_accepts_minor_version_and_additive_fields(
    terraform_project: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    payload = _validation_json(format_version=version, future_property={"example": True})
    _validator(monkeypatch, CommandResult((), 0, payload, ""))
    report = iac_repo_gate.build_report(terraform_project, run_optional_tools=False)
    assert report.status == "pass"
    assert report.metadata.partial is False
    assert report.extensions["tools"]["tofu"]["validated"] is True


def test_terraform_ignores_unknown_diagnostic_severity(
    terraform_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _validation_json(
        diagnostics=[{"severity": "experimental", "summary": "Future diagnostic"}]
    )
    _validator(monkeypatch, CommandResult((), 0, payload, ""))
    report = iac_repo_gate.build_report(terraform_project, run_optional_tools=False)
    assert report.status == "pass"
    assert report.metadata.partial is False
    assert report.extensions["tools"]["tofu"]["validated"] is True
    assert not report.findings
