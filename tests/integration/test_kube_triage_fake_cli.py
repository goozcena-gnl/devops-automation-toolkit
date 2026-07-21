from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from devops_toolkit.commands.kube_triage import build_report
from devops_toolkit.core.models import Severity

FAKE_KUBECTL = r"""#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
if args[:4] == ["config", "get-contexts", "-o", "name"]:
    print("development-cluster")
    raise SystemExit(0)
if args[:2] == ["config", "current-context"]:
    print("development-cluster")
    raise SystemExit(0)
if "get" not in args:
    print("unsupported command", file=sys.stderr)
    raise SystemExit(2)
resource = args[args.index("get") + 1]
key_by_resource = {
    "nodes": "nodes",
    "pods": "pods",
    "deployments": "deployments",
    "statefulsets": "statefulsets",
    "daemonsets": "daemonsets",
    "jobs": "jobs",
    "persistentvolumeclaims": "pvcs",
    "events": "events",
    "endpoints": "endpoints",
}
with open(os.environ["FAKE_KUBE_FIXTURE"], encoding="utf-8") as handle:
    payload = json.load(handle)
print(json.dumps(payload[key_by_resource[resource]]))
"""


@pytest.mark.integration
def test_kube_triage_uses_read_only_kubectl_collection(
    repository_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        script = tmp_path / "fake-kubectl.py"
        script.write_text(FAKE_KUBECTL, encoding="utf-8")
        executable = tmp_path / "kubectl.cmd"
        executable.write_text(
            f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
            encoding="utf-8",
        )
    else:
        executable = tmp_path / "kubectl"
        executable.write_text(FAKE_KUBECTL, encoding="utf-8")
        executable.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv(
        "FAKE_KUBE_FIXTURE",
        str(repository_root / "tests/fixtures/kubernetes/collection.json"),
    )

    report, collections = build_report(
        context="development-cluster",
        namespace="default",
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
