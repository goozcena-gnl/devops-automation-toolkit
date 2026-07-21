import json

from typer.testing import CliRunner

from devops_toolkit.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.stdout


def test_validate_config_command(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "validate-config",
            "--config",
            str(repository_root / "configs/examples/toolkit.example.yaml"),
        ],
    )
    assert result.exit_code == 0
    assert '"version": 1' in result.stdout


def test_redact_requires_one_input() -> None:
    result = runner.invoke(app, ["redact"])
    assert result.exit_code == 2


def test_render_sample_json() -> None:
    result = runner.invoke(app, ["render-sample", "--format", "json"])
    assert result.exit_code == 0
    assert '"schema_version": "1.0"' in result.stdout


def test_secret_sentinel_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "secret-sentinel",
            str(repository_root / "tests/fixtures/secret-repo"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert '"tool": "secret-sentinel"' in result.stdout


def test_gha_guard_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "gha-guard",
            str(repository_root / "tests/fixtures/gha-repo"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "GHA-PULL-REQUEST-TARGET" in result.stdout


def test_kube_triage_blocks_namespace_outside_configured_allowlist(tmp_path) -> None:
    config = tmp_path / "toolkit.yaml"
    config.write_text(
        """version: 1
tools:
  kube-triage:
    allowed_namespaces: [default]
""",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "kube-triage",
            "--config",
            str(config),
            "--namespace",
            "payments",
        ],
    )
    assert result.exit_code == 7
    assert "not in the configured allowlist" in result.output


def test_tool_uses_configured_json_format(repository_root, tmp_path) -> None:
    config = tmp_path / "toolkit.yaml"
    config.write_text(
        """version: 1
defaults:
  format: json
  no_color: true
""",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "gha-guard",
            str(repository_root / "tests/fixtures/gha-repo"),
            "--config",
            str(config),
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["metadata"]["tool"] == "gha-guard"


def test_cli_format_overrides_configuration(repository_root, tmp_path) -> None:
    config = tmp_path / "toolkit.yaml"
    config.write_text(
        """version: 1
defaults:
  format: markdown
""",
        encoding="utf-8",
    )
    output = tmp_path / "gha.json"
    result = runner.invoke(
        app,
        [
            "gha-guard",
            str(repository_root / "tests/fixtures/gha-repo"),
            "--config",
            str(config),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 1
    assert json.loads(output.read_text(encoding="utf-8"))["metadata"]["tool"] == "gha-guard"


def test_plan_risk_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "plan-risk",
            str(repository_root / "tests/fixtures/terraform-plan/risky.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "TFPLAN-PUBLIC-EXPOSURE" in result.stdout


def test_repo_baseline_snapshot_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "repo-baseline",
            "--snapshot",
            str(repository_root / "tests/fixtures/github/insecure-repository.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "GITHUB-ACTIONS-DEFAULT-WRITE" in result.stdout


def test_image_gate_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "image-gate",
            "example.invalid/app:1.0",
            "--trivy-json",
            str(repository_root / "tests/fixtures/image/trivy.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "IMAGE-EMBEDDED-SECRET" in result.stdout
    assert "SYNTHETIC_SECRET_VALUE_MUST_NOT_APPEAR" not in result.stdout


def test_ci_evidence_cli(repository_root) -> None:
    fixture = repository_root / "tests/fixtures/ci-logs"
    result = runner.invoke(
        app,
        [
            "ci-evidence",
            "--logs-dir",
            str(fixture),
            "--metadata",
            str(fixture / "metadata.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "CI-OUT-OF-MEMORY" in result.stdout
    assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in result.stdout


def test_prom_audit_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "prom-audit",
            "--snapshot",
            str(repository_root / "tests/fixtures/prometheus/snapshot.json"),
            "--expected-job",
            "missing",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "PROM-TARGET-DOWN" in result.stdout


def test_slo_budget_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "slo-budget",
            str(repository_root / "tests/fixtures/slo/spec.yaml"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "SLO-ERROR-BUDGET-EXHAUSTED" in result.stdout


def test_kube_rightsize_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "kube-rightsize",
            "--snapshot",
            str(repository_root / "tests/fixtures/kubernetes-rightsize/snapshot.json"),
            "--patch-preview",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "KUBE-MEMORY-LIMIT-RISK" in result.stdout
    assert '"patch_preview"' in result.stdout


def test_cloud_iam_audit_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "cloud-iam-audit",
            "--provider",
            "azure",
            "--snapshot",
            str(repository_root / "tests/fixtures/cloud/azure-iam-risky.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "AZURE-IAM-BROAD-PRIVILEGED-ROLE" in result.stdout


def test_cloud_waste_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "cloud-waste",
            "--provider",
            "aws",
            "--snapshot",
            str(repository_root / "tests/fixtures/cloud/aws-waste-risky.json"),
            "--required-tag",
            "owner",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "CLOUD-WASTE-UNATTACHED-STORAGE" in result.stdout


def test_budget_guard_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "budget-guard",
            "--provider",
            "aws",
            "--snapshot",
            str(repository_root / "tests/fixtures/cloud/aws-budget-risky.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "CLOUD-BUDGET-EXCEEDED" in result.stdout


def test_iac_drift_guard_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "iac-drift-guard",
            str(repository_root),
            "--plan-json",
            str(repository_root / "tests/fixtures/terraform-drift/drift.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "IAC-DRIFT-REMOTE-DELETION" in result.stdout


def test_kube_upgrade_readiness_cli(repository_root) -> None:
    result = runner.invoke(
        app,
        [
            "kube-upgrade-readiness",
            "--target-version",
            "1.33.0",
            "--snapshot",
            str(repository_root / "tests/fixtures/kubernetes-upgrade/snapshot.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert "KUBE-UPGRADE-REMOVED-API-USAGE" in result.stdout
