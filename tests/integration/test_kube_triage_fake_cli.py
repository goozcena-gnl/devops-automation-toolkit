from __future__ import annotations

import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devops_toolkit.cli import app
from devops_toolkit.commands.kube_triage import build_report
from devops_toolkit.core.kubernetes import KubernetesReadPolicy
from devops_toolkit.core.models import Severity

FAKE_KUBECTL = r"""#!/usr/bin/env python3
import json
import os
import sys
import time

args = sys.argv[1:]
with open(os.environ["FAKE_KUBE_CALLS"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\n")
if args[:2] == ["config", "view"]:
    print(json.dumps({
        "current": os.environ.get("FAKE_CURRENT_CONTEXT", "development-cluster"),
        "contexts": [["development-cluster", "sandbox"], ["staging-cluster", "staging"]],
        "clusters": [
            ["sandbox", "https://sandbox.example.invalid", "sandbox-tls.example.invalid"],
            ["staging", "https://staging.example.invalid", ""],
        ],
    }))
    raise SystemExit(0)
if args[:4] != [
    "--context=development-cluster", "--cluster=sandbox",
    "--server=https://sandbox.example.invalid", "--tls-server-name=sandbox-tls.example.invalid",
]:
    raise SystemExit("unexpected Kubernetes target")
if args[4:] == ["version", "-o", "json"]:
    version = {"gitVersion": "v1.32.0"}
    print(json.dumps({"clientVersion": version, "serverVersion": version}))
    raise SystemExit(0)
if args[4:] == ["api-versions"]:
    print("v1\napps/v1\nexample.invalid/foo1")
    raise SystemExit(0)
if args[4:5] == ["get"] and args[-2:] == ["-o", "json"]:
    if args[5:-2] not in [
        ["nodes"], ["poddisruptionbudgets.policy", "-A"],
        ["customresourcedefinitions.apiextensions.k8s.io"],
        ["mutatingwebhookconfigurations.admissionregistration.k8s.io"],
        ["validatingwebhookconfigurations.admissionregistration.k8s.io"],
        ["apiservices.apiregistration.k8s.io"],
        ["deployments,statefulsets,daemonsets", "-n", "kube-system"],
    ]:
        raise SystemExit("unexpected upgrade resource")
    print('{"items":[]}')
    raise SystemExit(0)
if args[4:6] != ["get", "--raw"] or len(args) != 7:
    raise SystemExit("unexpected Kubernetes operation")
route = args[-1]
resource = route.rsplit("/", 1)[-1]
mode = os.environ.get("FAKE_KUBE_RESPONSE", "valid")
canary = "ghp_123456789012345678901234567890"
if mode == "unauthorized":
    print("error: You must be logged in to the server (the server has asked for credentials)", file=sys.stderr)
    raise SystemExit(1)
if mode == "timeout":
    time.sleep(5)
if mode == "forbidden":
    print(f"Error from server (Forbidden): {canary}", file=sys.stderr)
    raise SystemExit(1)
if mode == "malformed":
    print("{{" + canary)
    raise SystemExit(0)
if mode == "truncated":
    print(" " * 10_000_100)
    raise SystemExit(0)
if mode == "unexpected":
    print("[]")
    raise SystemExit(0)
if route.startswith("/apis/metrics.k8s.io/"):
    namespace = "finance" if mode == "wrong-metrics-namespace" else "payments"
    print(json.dumps({"items": [{"metadata": {"namespace": namespace, "name": canary}}]}))
    raise SystemExit(0)
key = "pvcs" if resource == "persistentvolumeclaims" else resource
with open(os.environ["FAKE_KUBE_FIXTURE"], encoding="utf-8") as handle:
    payload = json.load(handle)
print(json.dumps(payload[key]))
"""


@pytest.fixture
def fake_kubectl(repository_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    if os.name == "nt":
        from pip._vendor.distlib.scripts import ScriptMaker

        script = tmp_path / "fake_kubectl.py"
        script.write_text(
            "def main():\n" + "".join(f"    {line}\n" for line in FAKE_KUBECTL.splitlines()[1:]),
            encoding="utf-8",
        )
        maker = ScriptMaker(None, str(tmp_path))
        maker.executable = sys.executable
        maker.variants = {""}
        [launcher] = maker.make("kubectl = fake_kubectl:main")
        executable = Path(launcher)
        monkeypatch.setenv(
            "PYTHONPATH", f"{tmp_path}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"
        )
        monkeypatch.setenv("PATH", str(tmp_path))
    else:
        executable = tmp_path / "kubectl"
        executable.write_text(
            f"#!{sys.executable}\n" + FAKE_KUBECTL.split("\n", 1)[1], encoding="utf-8"
        )
        executable.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
    discovered = shutil.which("kubectl")
    assert discovered is not None
    assert os.path.samefile(discovered, executable)
    calls = tmp_path / "kubectl-calls.jsonl"
    calls.touch()
    monkeypatch.setenv("FAKE_KUBE_CALLS", str(calls))
    monkeypatch.setenv(
        "FAKE_KUBE_FIXTURE",
        str(repository_root / "tests/fixtures/kubernetes/collection.json"),
    )
    return calls


def _calls(path: Path) -> list[list[str]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _assert_example(report: dict, path: Path) -> None:
    expected = json.loads(path.read_text(encoding="utf-8"))
    for field in ("started_at", "completed_at"):
        report["metadata"][field] = expected["metadata"][field]
    assert report == expected


@pytest.mark.integration
def test_kube_triage_uses_read_only_kubectl_collection(fake_kubectl: Path) -> None:
    report, collections = build_report(
        context="development-cluster",
        namespace="payments",
        read_policy=KubernetesReadPolicy(allow_cluster_scope=True),
        threshold=Severity.HIGH,
        timeout_seconds=5,
    )

    assert report.metadata.target == "development-cluster"
    assert report.metadata.partial is False
    assert report.status.value == "fail"
    assert set(collections) == {
        "nodes",
        "pods",
        "deployments",
        "statefulsets",
        "daemonsets",
        "jobs",
        "pvcs",
        "events",
        "endpoints",
    }

    calls = _calls(fake_kubectl)
    assert calls[0][:2] == ["config", "view"]
    assert calls[1][4:] == ["get", "--raw", "/api/v1/nodes"]
    assert all("/namespaces/payments/" in call[-1] for call in calls[2:])


@pytest.mark.integration
@pytest.mark.parametrize("context_args", [[], ["--context", "staging-cluster"]])
def test_context_allowlist_blocks_cli_before_api(
    fake_kubectl: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, context_args: list[str]
) -> None:
    monkeypatch.setenv("FAKE_CURRENT_CONTEXT", "staging-cluster")
    config = tmp_path / "policy.yaml"
    config.write_text(
        "version: 1\ntools:\n  kube-upgrade-readiness:\n"
        "    allow_cluster_scope: true\n    allowed_contexts: [development-cluster]\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        [
            "kube-upgrade-readiness",
            "--target-version",
            "1.33.0",
            "--config",
            str(config),
            *context_args,
        ],
    )
    assert result.exit_code == 7
    assert all(call[:2] == ["config", "view"] for call in _calls(fake_kubectl))


@pytest.mark.integration
@pytest.mark.parametrize(
    ("mode", "code", "expected"),
    [
        ("valid", 0, ""),
        ("wrong-metrics-namespace", 5, "outside the authorized scope"),
        ("forbidden", 4, "denied authentication or authorization"),
        ("unauthorized", 4, "denied authentication or authorization"),
        ("timeout", 5, "timed out"),
        ("malformed", 5, "invalid JSON"),
        ("unexpected", 5, "unexpected JSON response"),
        ("truncated", 5, "was truncated"),
    ],
)
def test_rightsize_cli_enforces_request_and_response_scope(
    repository_root: Path,
    fake_kubectl: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    code: int,
    expected: str,
) -> None:
    monkeypatch.setenv("FAKE_KUBE_RESPONSE", mode)
    result = CliRunner().invoke(
        app,
        [
            "kube-rightsize",
            "--context",
            "development-cluster",
            "--namespace",
            "payments",
            "--format",
            "json",
            "--timeout",
            "2",
        ],
    )
    assert result.exit_code == code, result.output
    assert expected in result.output
    assert "ghp_123456789012345678901234567890" not in result.output
    calls = _calls(fake_kubectl)
    assert calls[0][:2] == ["config", "view"]
    expected_paths = ["/api/v1/namespaces/payments/pods"]
    if mode in {"valid", "wrong-metrics-namespace"}:
        expected_paths.append("/apis/metrics.k8s.io/v1beta1/namespaces/payments/pods")
    assert [call[-1] for call in calls[1:]] == expected_paths
    if code != 4:
        report = json.loads(result.stdout)
        assert report["schema_version"] == "1.0"
        assert report["metadata"]["partial"] == (mode != "valid")
        if mode == "wrong-metrics-namespace":
            _assert_example(
                report, repository_root / "examples/reports/phase5/kube-rightsize-read-scope.json"
            )


@pytest.mark.integration
def test_offline_cli_ignores_current_context_and_kubectl(
    repository_root: Path, fake_kubectl: Path
) -> None:
    result = CliRunner().invoke(
        app,
        [
            "kube-upgrade-readiness",
            "--target-version",
            "1.33.0",
            "--snapshot",
            str(repository_root / "tests/fixtures/kubernetes-upgrade/snapshot.json"),
            "--context",
            "another-cluster",
        ],
    )
    assert result.exit_code == 1
    assert not _calls(fake_kubectl)


@pytest.mark.integration
def test_live_upgrade_requires_opt_in_and_uses_only_approved_requests(
    repository_root: Path, fake_kubectl: Path, tmp_path: Path
) -> None:
    arguments = ["kube-upgrade-readiness", "--target-version", "1.33.0", "--format", "json"]
    assert CliRunner().invoke(app, arguments).exit_code == 7
    assert len(_calls(fake_kubectl)) == 1
    config = tmp_path / "scope.yaml"
    config.write_text(
        "version: 1\ntools:\n  kube-upgrade-readiness:\n    allow_cluster_scope: true\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, [*arguments, "--config", str(config)])
    assert result.exit_code == 5, result.output
    report = json.loads(result.stdout)
    assert report["metadata"]["target"] == "development-cluster->1.33.0"
    assert report["extensions"]["scope"]["addon_namespace"] == "kube-system"
    assert len(report["extensions"]["collection_notes"]) == 1
    _assert_example(
        report, repository_root / "examples/reports/phase6/kube-upgrade-readiness-read-scope.json"
    )
    calls = _calls(fake_kubectl)[2:]
    assert len(calls) == 9
    assert calls[0][4:] == ["version", "-o", "json"]
    assert calls[-1][4:] == [
        "get",
        "deployments,statefulsets,daemonsets",
        "-n",
        "kube-system",
        "-o",
        "json",
    ]


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
def test_rejected_payload_never_reaches_output_or_triage_bundle(
    repository_root: Path, fake_kubectl: Path, tmp_path: Path, report_format: str
) -> None:
    bundle = tmp_path / "triage.zip"
    result = CliRunner().invoke(
        app,
        [
            "kube-triage",
            "--context",
            "development-cluster",
            "--namespace",
            "default",
            "--format",
            report_format,
            "--bundle",
            str(bundle),
        ],
    )
    assert result.exit_code == 5
    assert "payments" not in result.stdout
    assert not any(call[-1] == "/api/v1/nodes" for call in _calls(fake_kubectl))
    with zipfile.ZipFile(bundle) as archive:
        assert "evidence/pods.json" not in archive.namelist()
        report = json.loads(archive.read("report.json"))
    _assert_example(report, repository_root / "examples/reports/phase3/kube-triage-read-scope.json")
    assert report["extensions"]["collection_exclusions"] == {"nodes": "intentionally_excluded"}
    assert "outside the authorized scope" in report["extensions"]["collection_errors"]["pods"]


@pytest.mark.integration
def test_ordered_config_and_explicit_context_precedence(fake_kubectl: Path, tmp_path: Path) -> None:
    first = tmp_path / "first.yaml"
    first.write_text(
        "version: 1\ntools:\n  kube-rightsize:\n"
        "    allowed_contexts: [staging-cluster]\n    allowed_namespaces: [finance]\n",
        encoding="utf-8",
    )
    second = tmp_path / "second.yaml"
    second.write_text(
        "version: 1\ntools:\n  kube-rightsize:\n"
        "    allowed_contexts: [development-cluster]\n    allowed_namespaces: [payments]\n",
        encoding="utf-8",
    )
    args = ["kube-rightsize", "--context", "development-cluster", "--namespace", "payments"]
    result = CliRunner().invoke(app, [*args, "--config", str(first), "--config", str(second)])
    assert result.exit_code == 0, result.output
    calls = _calls(fake_kubectl)
    assert len(calls) == 3
    result = CliRunner().invoke(app, [*args, "--config", str(second), "--config", str(first)])
    assert result.exit_code == 7
    assert _calls(fake_kubectl)[:-1] == calls
    assert _calls(fake_kubectl)[-1][:2] == ["config", "view"]
