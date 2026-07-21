from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from devops_toolkit.cli import app

runner = CliRunner()


@pytest.mark.parametrize(
    "arguments",
    [
        ["plan-risk", "{invalid}"],
        ["repo-baseline", "--snapshot", "{invalid}"],
        ["image-gate", "example.invalid/app:1", "--trivy-json", "{invalid}"],
        ["prom-audit", "--snapshot", "{invalid}"],
        ["kube-rightsize", "--snapshot", "{invalid}"],
        ["cloud-iam-audit", "--provider", "aws", "--snapshot", "{invalid}"],
        ["cloud-waste", "--provider", "aws", "--snapshot", "{invalid}"],
        ["budget-guard", "--provider", "aws", "--snapshot", "{invalid}"],
        ["iac-drift-guard", ".", "--plan-json", "{invalid}"],
        [
            "kube-upgrade-readiness",
            "--target-version",
            "1.33.0",
            "--snapshot",
            "{invalid}",
        ],
    ],
)
def test_malformed_json_inputs_fail_without_tracebacks(
    tmp_path: Path, arguments: list[str]
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{invalid", encoding="utf-8")
    resolved = [str(invalid) if item == "{invalid}" else item for item in arguments]

    result = runner.invoke(app, resolved)

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "Unable to read" in result.output


def test_malformed_kubeconfig_fails_without_traceback(tmp_path: Path) -> None:
    kubeconfig = tmp_path / "kubeconfig.yaml"
    kubeconfig.write_text(": broken: [", encoding="utf-8")

    result = runner.invoke(app, ["kubeconfig-hygiene", "--kubeconfig", str(kubeconfig)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "Unable to parse kubeconfig" in result.output


@pytest.mark.parametrize(
    "arguments,dependency",
    [
        (["image-gate", "example.invalid/app:1"], "trivy"),
        (["repo-baseline", "owner/repository"], "gh"),
        (["kube-triage", "--context", "development", "--namespace", "default"], "kubectl"),
    ],
)
def test_missing_dependencies_use_exit_code_three(arguments: list[str], dependency: str) -> None:
    result = runner.invoke(app, arguments, env={"PATH": ""})

    assert result.exit_code == 3
    assert "Traceback" not in result.output
    assert dependency in result.output
