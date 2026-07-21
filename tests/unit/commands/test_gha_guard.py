from __future__ import annotations

from devops_toolkit.commands.gha_guard import build_report
from devops_toolkit.core.models import Severity


def test_gha_guard_detects_insecure_workflow(repository_root) -> None:
    report = build_report(
        repository_root / "tests/fixtures/gha-repo",
        threshold=Severity.HIGH,
    )
    identifiers = {finding.id for finding in report.findings}
    assert "GHA-PULL-REQUEST-TARGET" in identifiers
    assert "GHA-PERMISSIONS-WRITE-ALL" in identifiers
    assert "GHA-ACTION-NOT-SHA-PINNED" in identifiers
    assert "GHA-UNTRUSTED-INPUT-IN-SHELL" in identifiers
    assert report.status.value == "fail"


def test_gha_guard_requires_docker_action_digest(tmp_path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "docker.yml").write_text(
        """name: Docker action
on: [push]
permissions:
  contents: read
concurrency:
  group: docker
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: docker://alpine:3.22
""",
        encoding="utf-8",
    )
    report = build_report(tmp_path, threshold=Severity.HIGH)
    assert any(finding.id == "GHA-DOCKER-ACTION-NOT-DIGEST-PINNED" for finding in report.findings)
