from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.integration
@pytest.mark.parametrize("installed", [False, True], ids=["module", "installed"])
def test_cli_reports_incomplete_secret_collection(tmp_path: Path, installed: bool) -> None:
    command = [sys.executable, "-m", "devops_toolkit"]
    if installed:
        executable = shutil.which("devops-toolkit")
        assert executable is not None, "Install the package before running integration tests"
        command = [executable]
    (tmp_path / "large.txt").write_bytes(b"x" * 1025)
    result = subprocess.run(
        [
            *command,
            "secret-sentinel",
            str(tmp_path),
            "--format",
            "json",
            "--max-file-bytes",
            "1024",
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert result.returncode == 5, result.stderr
    report = json.loads(result.stdout)
    assert report["schema_version"] == "1.0"
    assert report["metadata"]["partial"]


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="synthetic POSIX executable uses a Python shebang")
@pytest.mark.parametrize(
    ("has_version", "expected_exit"),
    [(True, 0), (False, 5)],
    ids=["complete", "incomplete"],
)
def test_iac_real_cli_invokes_synthetic_terraform_validator(
    tmp_path: Path, has_version: bool, expected_exit: int
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / ".terraform").mkdir()
    (root / ".terraform.lock.hcl").touch()
    (root / "main.tf").write_text(
        'terraform {\n  required_version = ">= 1.8"\n}\n', encoding="utf-8"
    )
    payload: dict[str, object] = {
        "format_version": "1.0",
        "valid": True,
        "error_count": 0,
        "warning_count": 0,
        "diagnostics": [],
    }
    if not has_version:
        payload.pop("format_version")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    executable = fake_bin / "tofu"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if sys.argv[1] == 'fmt':\n"
        "    sys.exit(0)\n"
        "if sys.argv[1:] == ['validate', '-json']:\n"
        f"    print({json.dumps(payload)!r})\n"
        "    sys.exit(0)\n"
        "sys.exit(9)\n",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    env = dict(os.environ)
    env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "devops_toolkit",
            "iac-repo-gate",
            str(root),
            "--no-optional-tools",
            "--format",
            "json",
        ],
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=30,
        env=env,
    )
    assert completed.returncode == expected_exit, completed.stderr
    report = json.loads(completed.stdout)
    tools = report["extensions"]["tools"]["tofu"]
    assert report["schema_version"] == "1.0"
    assert report["metadata"]["partial"] is (not has_version)
    assert tools["validated"] is has_version
    assert tools["validation_state"] == ("complete" if has_version else "failed")
    assert tools["validation_reason"] == ("validated" if has_version else "invalid_format_version")
