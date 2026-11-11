from __future__ import annotations

import json
import shutil
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
