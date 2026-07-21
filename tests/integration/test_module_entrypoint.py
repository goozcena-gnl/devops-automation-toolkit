from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.integration
def test_module_entrypoint_preserves_finding_exit_code(
    repository_root: Path, tmp_path: Path
) -> None:
    output = tmp_path / "secret-report.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "devops_toolkit",
            "secret-sentinel",
            str(repository_root / "tests/fixtures/secret-repo"),
            "--format",
            "json",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 1
    assert output.exists()
