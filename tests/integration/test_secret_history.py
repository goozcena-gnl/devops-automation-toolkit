from __future__ import annotations

import shutil
import subprocess

import pytest

from devops_toolkit.commands.secret_sentinel import build_report
from devops_toolkit.core.models import Severity


@pytest.mark.integration
def test_secret_sentinel_detects_removed_secret_in_git_history(tmp_path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is unavailable")

    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True)
    subprocess.run([git, "config", "user.name", "Toolkit Test"], cwd=tmp_path, check=True)
    subprocess.run(
        [git, "config", "user.email", "toolkit-test@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    secret_file = tmp_path / "removed.env"
    secret_file.write_text(f"GITHUB_TOKEN={secret}\n", encoding="utf-8")
    subprocess.run([git, "add", "removed.env"], cwd=tmp_path, check=True)
    subprocess.run([git, "commit", "-qm", "add synthetic fixture"], cwd=tmp_path, check=True)
    secret_file.unlink()
    subprocess.run([git, "add", "-u"], cwd=tmp_path, check=True)
    subprocess.run([git, "commit", "-qm", "remove synthetic fixture"], cwd=tmp_path, check=True)

    report = build_report(
        tmp_path,
        history=True,
        max_commits=10,
        threshold=Severity.HIGH,
    )

    assert any(finding.id == "SECRET-GITHUB-TOKEN" for finding in report.findings)
    assert report.extensions["metrics"]["commits_scanned"] == 2
    assert secret not in str(report.as_dict())


@pytest.mark.integration
def test_secret_sentinel_honors_exclusions_in_git_history(tmp_path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is unavailable")

    subprocess.run([git, "init", "-q", str(tmp_path)], check=True)
    subprocess.run([git, "config", "user.name", "Toolkit Test"], cwd=tmp_path, check=True)
    subprocess.run(
        [git, "config", "user.email", "toolkit-test@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    excluded = tmp_path / "excluded"
    excluded.mkdir()
    secret_file = excluded / "removed.env"
    secret_file.write_text(
        "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n",
        encoding="utf-8",
    )
    subprocess.run([git, "add", "excluded/removed.env"], cwd=tmp_path, check=True)
    subprocess.run([git, "commit", "-qm", "add excluded fixture"], cwd=tmp_path, check=True)

    report = build_report(
        tmp_path,
        history=True,
        max_commits=10,
        threshold=Severity.HIGH,
        excluded_dirs={"excluded"},
    )

    assert not report.findings
    assert report.extensions["metrics"]["commits_scanned"] == 1
