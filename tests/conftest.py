from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def latest_ci_inputs(tmp_path: Path) -> tuple[Path, Path, dict[str, str], list[str]]:
    source = tmp_path / "token=CANARY_TARGET_HEAD CANARY_TARGET_TAIL" / "ordinary directory"
    source.mkdir(parents=True)
    fragments = ["CANARY_HEAD", "CANARY_TAIL", "CANARY_TARGET_HEAD", "CANARY_TARGET_TAIL"]
    names = [
        "token=CANARY_HEAD CANARY_TAIL",
        "password=CANARY_HEAD CANARY_TAIL/child.log",
        "ordinary/token=CANARY_HEAD CANARY_TAIL/job.log",
        "token=CANARY_HEAD CANARY_TAIL.log",
        "[REDACTED].log",
        "ordinary directory/plain.log",
    ]
    raw = {name: f"exit code 137 tests failed job {index}\n" for index, name in enumerate(names)}
    for name, content in raw.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    metadata = tmp_path / "latest-metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "run": {
                    "token=CANARY_HEAD": {"code": 137},
                    "token=CANARY_TAIL": {"code": 1},
                    "[REDACTED]": {"code": 7},
                    "ordinary": [7, True, None],
                    "artifact_paths": [
                        "ordinary/token=CANARY_HEAD CANARY_TAIL/job.log",
                        {"logPath": r"C:\ordinary\token=CANARY_HEAD CANARY_TAIL\job.log"},
                    ],
                },
                "jobs": [
                    {
                        "id": 1,
                        "name": 'tests failed path="unmatched {"password":"CANARY_HEAD CANARY_TAIL"}',
                        "conclusion": "failure",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return source, metadata, raw, fragments


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


@pytest.fixture(params=["identical", "ancestor-malformed-prefix"])
def collision_ci_inputs(
    tmp_path: Path, request: pytest.FixtureRequest
) -> tuple[Path, Path, dict[str, str], list[str]]:
    logs = tmp_path / "collision-logs"
    logs.mkdir()
    secrets = [f"CANARY{index}" for index in range(4)]
    raw_logs = {
        f"ordinary/{['password', 'Password', 'PASSWORD', 'password'][index]}={secret}.log": (
            f"exit code 137 job {index}\n" + json.dumps({"token": secret}) + "\n"
        )
        for index, secret in enumerate(secrets)
    }
    raw_logs["ordinary/plain.log"] = "exit code 137 ordinary job\n"
    if request.param == "ancestor-malformed-prefix":
        secrets.append("CANARY_PREFIX_BYPASS")
        content = (
            r'exit code 137 tests failed path="C:\work" '
            '{"password":"CANARY_PREFIX_BYPASS","count":7}'
            "\n"
            'tests failed path="unmatched {"password":"CANARY_PREFIX_BYPASS","count":7}'
            "\nexit code 137\n"
        )
        for _ in range(3):
            content += json.dumps({"message": content, "ordinary": [7, True, None]}) + "\n"
        raw_logs.update(
            {
                "token=CANARY0 data/child.log": content,
                "token=CANARY1 data": content,
                "nested/token=CANARY2 DATA/child.log": content,
                "nested/token=CANARY3 data": content,
            }
        )
    for name, content in raw_logs.items():
        path = logs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    metadata = tmp_path / "collision-metadata.json"
    metadata.write_text(json.dumps({"run": {"token": secrets[0], "ordinary": 7}}), encoding="utf-8")
    return logs, metadata, raw_logs, secrets


@pytest.fixture
def punctuation_ci_inputs(tmp_path: Path) -> tuple[Path, Path, dict[str, str], list[str]]:
    """Provider punctuation plus existing shell/collision cases, using synthetic values only."""
    fragments = [f"CANARY_HEAD_{i}" for i in range(8)] + [f"CANARY_TAIL_{i}" for i in range(8)]
    source = tmp_path / "password=CANARY_HEAD_6&CANARY_TAIL_6" / "logs"
    source.mkdir(parents=True)
    values = [
        "password=CANARY_HEAD_0&CANARY_TAIL_0",
        "password=CANARY_HEAD_1(CANARY_TAIL_1)",
        "token=CANARY_HEAD_2|CANARY_TAIL_2",
        "secret=CANARY_HEAD_3<CANARY_TAIL_3",
        'password="CANARY_HEAD_4"CANARY_TAIL_4',
        "token='CANARY_HEAD_5'CANARY_TAIL_5",
        '"password=CANARY_HEAD_7"CANARY_TAIL_7',
        '"password":CANARY_HEAD_0;CANARY_TAIL_0',
        "'token':${CANARY_HEAD_1}&CANARY_TAIL_1",
        '"password":"CANARY_HEAD_0",CANARY_TAIL_0',
        '"password":123,CANARY_TAIL_1',
        '"password":["CANARY_HEAD_2"],CANARY_TAIL_2',
        '"password":{"raw":"CANARY_HEAD_3"},CANARY_TAIL_3',
        '"password":"CANARY_HEAD_4"]CANARY_TAIL_4',
        '"password":"CANARY_HEAD_5"}CANARY_TAIL_5',
    ]
    lines = ["exit code 137 ordinary start", *("tests failed " + value for value in values)]
    lines.extend(
        [
            json.dumps({"message": values[0], "ordinary": {"count": 7}}),
            json.dumps(json.dumps({"message": values[1], "ordinary": [7, True, None]})),
            json.dumps({"token": "CANARY_HEAD_2|CANARY_TAIL_2", "ordinary": 7}),
            "ordinary final context",
            "exit code 137 ordinary end",
        ]
    )
    for value in values[-6:]:
        encoded = value
        for _ in range(3):
            encoded = json.dumps({"message": encoded, "ordinary": [7, True, None]})
            lines.append("tests failed " + encoded)
    names = [
        "password=CANARY_HEAD_0&CANARY_TAIL_0.log",
        "password=CANARY_HEAD_1(CANARY_TAIL_1).log",
        "password=CANARY_HEAD_2;CANARY_TAIL_2.log",
        "password='CANARY_HEAD_3'CANARY_TAIL_3.log",
        "ordinary/job with spaces.log",
    ]
    raw_logs = {name: "\n".join(lines) + "\n" for name in names}
    for name, content in raw_logs.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    metadata = tmp_path / "punctuation-metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "run": {"name": values[0], "ordinary": [7, True, None]},
                "jobs": [{"id": 1, "name": values[2], "conclusion": "failure"}],
                "note": values[3],
                "encoded": json.dumps(json.dumps({"message": values[1]})),
                "fragments": values[-6:],
                "encoded_fragments": json.dumps(json.dumps(values[-6:])),
            }
        ),
        encoding="utf-8",
    )
    return source, metadata, raw_logs, fragments
