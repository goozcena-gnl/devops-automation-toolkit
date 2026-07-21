from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="Linux collector requires a POSIX host")
def test_linux_foundation_collector(repository_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "linux.json"
    completed = subprocess.run(
        [
            str(repository_root / "scripts/linux/linux-triage.sh"),
            "--timeout",
            "1",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metadata"]["tool"] == "linux-triage"
    assert "host" in payload["extensions"]
    assert payload["metadata"]["tool_version"] == "1.0.0"
