from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def structured_ci_inputs(tmp_path: Path) -> tuple[Path, Path, list[str]]:
    """Offline credentials with no provider-token syntax or real account data."""
    logs = tmp_path / "logs"
    logs.mkdir()
    secrets = [f"SYNTHETIC_B02_{index}_credential tail" for index in range(7)]
    line = "tests failed " + json.dumps({"password": secrets[0], "ordinary": "keep log context"})
    escaped = json.dumps(json.dumps({"client_secret": secrets[1], "count": 7}))
    (logs / "job.log").write_text(line + "\nrunner " + escaped + "\n", encoding="utf-8")
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "run": {
                    "id": 123,
                    "name": "synthetic run",
                    "token": secrets[2],
                    "ordinary": {"count": 7},
                },
                "jobs": [
                    {
                        "id": 456,
                        "name": json.dumps({"secret": secrets[3], "job": "unit"}),
                        "conclusion": "failure",
                        "steps": [
                            {"name": json.dumps({"api_key": secrets[4]}), "conclusion": "failure"}
                        ],
                    }
                ],
                "credentials": {"password": {"nested": secrets[5]}, "client_secret": [secrets[6]]},
            }
        ),
        encoding="utf-8",
    )
    return logs, metadata, secrets
