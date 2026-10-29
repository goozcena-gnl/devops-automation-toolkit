from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
@pytest.mark.parametrize(
    "boundary", ["\n", "\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
)
def test_cli_preserves_all_original_evidence_line_boundaries(
    tmp_path: Path, report_format: str, boundary: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    text = f'password="CANARY_HEAD{boundary}CANARY_TAIL"{boundary}exit code 137'
    (source / "job.log").write_text(text, encoding="utf-8", newline="\n")
    bundle = tmp_path / "lines.zip"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "devops_toolkit",
            "ci-evidence",
            "--logs-dir",
            str(source),
            "--bundle",
            str(bundle),
            "--format",
            report_format,
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    with zipfile.ZipFile(bundle) as archive:
        report = json.loads(archive.read("report.json"))
        content = archive.read("logs/job.log").decode()
        line = len(text.splitlines())
        assert report["findings"][0]["evidence"]["line"] == line == 3
        assert report["extensions"]["timeline"][0]["line"] == line
        assert content.splitlines()[line - 1] == "exit code 137"
        assert len(content.splitlines()) == len(text.splitlines())
        assert "CANARY" not in archive.read("report.json").decode() + content
    assert "CANARY" not in result.stdout + result.stderr
    if report_format == "sarif":
        location = json.loads(result.stdout)["runs"][0]["results"][0]["locations"][0]
        assert location["physicalLocation"]["region"]["startLine"] == 3


@pytest.mark.integration
@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity", "depth", "root", "jobs"])
def test_invalid_provider_metadata_cli_is_controlled(tmp_path: Path, value: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    run = tmp_path / "run.json"
    jobs = tmp_path / "jobs.json"
    payload = '{"token":"CANARY_PROVIDER","diagnostic":' + value + "}"
    if value == "depth":
        payload = '{"diagnostic":' + "[" * 66 + '"token=CANARY_PROVIDER"' + "]" * 66 + "}"
    elif value in {"root", "jobs"}:
        payload = "[]" if value == "root" else '{"id":7}'
    run.write_text(payload, encoding="utf-8")
    jobs.write_text('{"jobs":{}}' if value == "jobs" else '{"jobs":[]}', encoding="utf-8")
    gh = bin_dir / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        f"source = {str(jobs)!r} if '/jobs?' in sys.argv[-1] else {str(run)!r}\n"
        "print(pathlib.Path(source).read_text(encoding='utf-8'))\n",
        encoding="utf-8",
    )
    gh.chmod(0o700)
    bundle = tmp_path / "provider.zip"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "devops_toolkit",
            "ci-evidence",
            "--repository",
            "synthetic/repository",
            "--run-id",
            "7",
            "--bundle",
            str(bundle),
            "--no-color",
        ],
        env={**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 2
    assert "metadata" in result.stderr.lower()
    assert "CANARY" not in result.stdout + result.stderr
    assert "Traceback" not in result.stdout + result.stderr
    assert not bundle.exists()


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
@pytest.mark.parametrize(
    ("discussion", "text", "names"),
    [
        ("4375404531", "exit code 137", ["password=CANARY_A.log", "password=CANARY_B.log"]),
        ("4377875048", 'token="CANARY_HEAD"CANARY_TAIL\nexit code 137', ["job.log"]),
        ("4382217579", "token=CANARY_HEAD&CANARY_TAIL\nexit code 137", ["job.log"]),
        ("4405115875", "exit code 137", ["token=CANARY_A data/child.log", "token=CANARY_B data"]),
        (
            "4405115967",
            'path="unmatched {"password":"CANARY_HEAD CANARY_TAIL"}\nexit code 137',
            ["job.log"],
        ),
        ("4406286098", "exit code 137", ["job.log"]),
        (
            "4406286152",
            "exit code 137",
            [
                "token=CANARY_HEAD\tCANARY_TAIL.log",
                "token='CANARY_HEAD'CANARY_TAIL/job.log",
                "ordinary/token=CANARY_HEAD\tCANARY_TAIL/child.log",
                'ordinary/"password":"CANARY_HEAD CANARY_TAIL".log',
            ],
        ),
        ("4406286200", "exit code 137", ["job.log"]),
        ("4406884173", "exit code 137", ["password=CANARY_DIRECT.log", "[REDACTED].log"]),
        ("4406884220", "exit code 137", ["job.log"]),
    ],
)
def test_ten_review_discussions_end_to_end(
    tmp_path: Path, report_format: str, discussion: str, text: str, names: list[str]
) -> None:
    from datetime import UTC, datetime

    from devops_toolkit.commands.ci_evidence import write_bundle
    from devops_toolkit.core.models import Report

    source = tmp_path / "token=CANARY_TARGET_HEAD CANARY_TARGET_TAIL" / "logs"
    source.mkdir(parents=True)
    for index, name in enumerate(names):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + f"\nordinary diagnostic {index}\n", encoding="utf-8", newline="\n")
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "run": {
                    "token=CANARY_KEY_A": {"code": 137},
                    "token=CANARY_KEY_B": {"code": 1},
                    "ordinary": [7, True, None],
                    "nested": [{"logPath": "ordinary/token=CANARY_HEAD\tCANARY_TAIL/job.log"}],
                    "invalid": float("nan") if discussion == "4406884220" else 7,
                }
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "token=CANARY_OUTPUT_HEAD CANARY_OUTPUT_TAIL"
    bundle = output_dir / "evidence.zip"
    output = output_dir / "rendered.txt"
    for file_output in [False, True]:
        args = [
            sys.executable,
            "-m",
            "devops_toolkit",
            "ci-evidence",
            "--logs-dir",
            str(source),
            "--metadata",
            str(metadata),
            "--bundle",
            str(bundle),
            "--format",
            report_format,
            "--no-color",
        ]
        if file_output:
            args.extend(["--output", str(output)])
        result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
        surfaces = [result.stdout, result.stderr]
        assert "Traceback" not in "".join(surfaces)
        if discussion == "4406884220":
            assert result.returncode == 2
            assert not bundle.exists()
            assert not output.exists()
        else:
            assert result.returncode == 1
            rendered = output.read_text() if file_output else result.stdout
            surfaces.append(rendered)
            with zipfile.ZipFile(bundle) as archive:
                members = archive.namelist()
                payload = json.loads(archive.read("report.json"))
                report_names = set(payload["extensions"]["log_files"])
                assert len(report_names) == len(names)
                assert {name[5:] for name in members if name.startswith("logs/")} == report_names
                assert {
                    item["source"] for item in payload["extensions"]["timeline"]
                } == report_names
                assert sorted(
                    item["code"]
                    for item in payload["extensions"]["run"].values()
                    if isinstance(item, dict)
                ) == [1, 137]
                for finding in payload["findings"]:
                    name = finding["resource"]["name"]
                    assert (
                        name == finding["resource"]["identifier"] == finding["evidence"]["location"]
                    )
                    assert members.count("logs/" + name) == 1
                    content = archive.read("logs/" + name).decode()
                    assert (
                        finding["evidence"]["summary"]
                        == content.splitlines()[finding["evidence"]["line"] - 1]
                    )
                if report_format == "json":
                    assert json.loads(rendered) == payload
                if report_format == "sarif":
                    assert json.loads(rendered)["version"] == "2.1.0"
                assert payload["schema_version"] == "1.0"
                surfaces.extend(members)
                surfaces.extend(archive.read(name).decode() for name in members)
            if discussion == "4406286098":

                class Unsupported:
                    def __str__(self) -> str:
                        raise AssertionError("Must not stringify unknown metadata")

                direct_metadata = {
                    "tuple": ("token=CANARY_TUPLE", Path("token=CANARY_HEAD CANARY_TAIL")),
                    "date": datetime(2026, 1, 1, tzinfo=UTC),
                    "nested": [{"object": Unsupported()}],
                }
                direct = tmp_path / "direct.zip"
                write_bundle(
                    direct, Report.model_validate(payload), {"job.log": text}, direct_metadata
                )
                with zipfile.ZipFile(direct) as archive:
                    surfaces.extend(archive.read(name).decode() for name in archive.namelist())
        assert all("CANARY" not in surface for surface in surfaces)


@pytest.mark.integration
@pytest.mark.parametrize(
    "value", ["NaN", "Infinity", "-Infinity", "depth", "parser-depth", "valid-depth"]
)
def test_metadata_cli_rejection_is_controlled_and_atomic(tmp_path: Path, value: str) -> None:
    source = tmp_path / "logs"
    source.mkdir()
    (source / "job.log").write_text("exit code 137", encoding="utf-8")
    metadata = tmp_path / "metadata.json"
    if value in {"depth", "parser-depth", "valid-depth"}:
        depth = {"depth": 65, "parser-depth": 2000, "valid-depth": 63}[value]
        payload = '{"run":' + "[" * depth + '"token=CANARY_INVALID"' + "]" * depth + "}"
    else:
        payload = '{"run":{"diagnostic":' + value + ',"token":"CANARY_INVALID"}}'
    metadata.write_text(payload, encoding="utf-8")
    bundle = tmp_path / "bundle.zip"
    output = tmp_path / "report.json"
    for existing in [False, True]:
        if existing:
            bundle.write_bytes(b"existing archive")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "devops_toolkit",
                "ci-evidence",
                "--logs-dir",
                str(source),
                "--metadata",
                str(metadata),
                "--bundle",
                str(bundle),
                "--output",
                str(output),
                "--format",
                "json",
                "--no-color",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        surfaces = result.stdout + result.stderr
        assert "CANARY" not in surfaces
        assert "Traceback" not in surfaces
        if value == "valid-depth":
            assert result.returncode == 1
            with zipfile.ZipFile(bundle) as archive:
                assert "CANARY" not in archive.read("report.json").decode()
            assert "CANARY" not in output.read_text()
        else:
            assert result.returncode == 2
            assert "metadata" in surfaces.lower()
            assert not output.exists()
            assert bundle.read_bytes() == b"existing archive" if existing else not bundle.exists()


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
def test_latest_metadata_and_paths_never_leak_or_lose_diagnostics(
    latest_ci_inputs: tuple[Path, Path, dict[str, str], list[str]],
    tmp_path: Path,
    report_format: str,
) -> None:
    source, metadata, raw, fragments = latest_ci_inputs
    fragments = [*fragments, "CANARY_OUTPUT_HEAD", "CANARY_OUTPUT_TAIL"]
    output_dir = tmp_path / "token=CANARY_OUTPUT_HEAD CANARY_OUTPUT_TAIL"
    for file_output in [False, True]:
        bundle = output_dir / f"latest-{file_output}.zip"
        output = output_dir / ("latest." + report_format)
        args = [
            sys.executable,
            "-m",
            "devops_toolkit",
            "ci-evidence",
            "--logs-dir",
            str(source),
            "--metadata",
            str(metadata),
            "--bundle",
            str(bundle),
            "--format",
            report_format,
            "--no-color",
        ]
        if file_output:
            args.extend(["--output", str(output)])
        completed = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
        assert completed.returncode == 1
        rendered = output.read_text(encoding="utf-8") if file_output else completed.stdout
        surfaces = [completed.stdout, completed.stderr, rendered]
        with zipfile.ZipFile(bundle) as archive:
            members = archive.namelist()
            report = json.loads(archive.read("report.json"))
            metadata_payload = json.loads(archive.read("metadata.json"))
            assert report["schema_version"] == "1.0"
            assert report["extensions"]["run"] == metadata_payload["run"]
            assert sorted(
                item["code"] for item in metadata_payload["run"].values() if isinstance(item, dict)
            ) == [1, 7, 137]
            names = set(report["extensions"]["log_files"])
            assert len(names) == len(raw)
            assert {name[5:] for name in members if name.startswith("logs/")} == names
            assert {item["source"] for item in report["extensions"]["timeline"]} == names
            for finding in report["findings"]:
                if finding["resource"]["type"] == "CILog":
                    name = finding["resource"]["name"]
                    assert name in names
                    assert (
                        finding["resource"]["identifier"] == finding["evidence"]["location"] == name
                    )
            if report_format == "json":
                assert json.loads(rendered) == report
            if report_format == "sarif":
                assert json.loads(rendered)["version"] == "2.1.0"
            surfaces.extend(members)
            surfaces.extend(archive.read(name).decode("utf-8") for name in members)
        assert all(fragment not in surface for fragment in fragments for surface in surfaces)


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
def test_ci_cli_redacts_structured_credentials_in_every_output(
    structured_ci_inputs: tuple[Path, Path, list[str]], tmp_path: Path, report_format: str
) -> None:
    logs, metadata, secrets = structured_ci_inputs
    bundle = tmp_path / "bundle.zip"
    output = tmp_path / ("report." + report_format)
    args = [
        sys.executable,
        "-m",
        "devops_toolkit",
        "ci-evidence",
        "--logs-dir",
        str(logs),
        "--metadata",
        str(metadata),
        "--format",
        report_format,
        "--no-color",
        "--bundle",
        str(bundle),
    ]
    for extra in ([], ["--output", str(output)]):
        result = subprocess.run(
            [*args, *extra], capture_output=True, text=True, check=False, timeout=30
        )
        assert result.returncode == 1
        surfaces = [result.stdout, result.stderr]
        if extra:
            surfaces.append(output.read_text(encoding="utf-8"))
        with zipfile.ZipFile(bundle) as archive:
            surfaces.extend(archive.namelist())
            surfaces.extend(archive.read(name).decode("utf-8") for name in archive.namelist())
        assert all(secret.split()[0] not in surface for secret in secrets for surface in surfaces)
        if report_format in {"json", "sarif"}:
            payload = json.loads(surfaces[2] if extra else result.stdout)
            assert payload.get("schema_version", payload.get("version")) in {"1.0", "2.1.0"}


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
@pytest.mark.parametrize(
    ("key", "marker"), [("password", "SYNTHETIC_B02_PATH"), ("token", "SYNTHETIC_B02_TOKEN")]
)
def test_log_directory_target_is_sanitized_on_every_cli_surface(
    tmp_path: Path, report_format: str, key: str, marker: str
) -> None:
    source = tmp_path / f"{key}={marker}" / "logs"
    source.mkdir(parents=True)
    (source / "job.log").write_text("exit code 137\nordinary context\n", encoding="utf-8")
    output = tmp_path / ("report." + report_format)
    surfaces: dict[str, str] = {}
    for mode in ["stdout", "file"]:
        bundle = tmp_path / (mode + "-evidence.zip")
        args = [
            sys.executable,
            "-m",
            "devops_toolkit",
            "ci-evidence",
            "--logs-dir",
            str(source),
            "--format",
            report_format,
            "--no-color",
            "--bundle",
            str(bundle),
        ]
        if mode == "file":
            args.extend(["--output", str(output)])
        result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=30)
        assert result.returncode == 1
        surfaces[mode + ":stdout"] = result.stdout
        surfaces[mode + ":stderr"] = result.stderr
        rendered = result.stdout if mode == "stdout" else output.read_text(encoding="utf-8")
        surfaces[mode + ":rendered"] = rendered
        if report_format in {"json", "sarif"}:
            payload = json.loads(rendered)
            assert payload.get("schema_version", payload.get("version")) in {"1.0", "2.1.0"}
        with zipfile.ZipFile(bundle) as archive:
            assert marker not in "\n".join(archive.namelist())
            for name in archive.namelist():
                member = archive.read(name).decode("utf-8")
                assert marker not in member
            bundled = json.loads(archive.read("report.json"))
            assert bundled["schema_version"] == "1.0"
            assert bundled["metadata"]["partial"] is False
            assert "[REDACTED]" in bundled["metadata"]["target"]
    leaks = [name for name, content in surfaces.items() if marker in "".join(content.split())]
    assert leaks == []


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
def test_collision_cli_keeps_report_and_archive_references_aligned(
    collision_ci_inputs: tuple[Path, Path, dict[str, str], list[str]],
    tmp_path: Path,
    report_format: str,
) -> None:
    source, metadata, raw_logs, secrets = collision_ci_inputs
    for output_mode in ["stdout", "file"]:
        bundle = tmp_path / (output_mode + "-collision.zip")
        output = tmp_path / ("collision-report." + report_format)
        args = [
            sys.executable,
            "-m",
            "devops_toolkit",
            "ci-evidence",
            "--logs-dir",
            str(source),
            "--metadata",
            str(metadata),
            "--bundle",
            str(bundle),
            "--format",
            report_format,
            "--no-color",
        ]
        if output_mode == "file":
            args.extend(["--output", str(output)])
        result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=30)
        assert result.returncode == 1
        rendered = result.stdout if output_mode == "stdout" else output.read_text(encoding="utf-8")
        surfaces = [result.stdout, result.stderr, rendered]
        with zipfile.ZipFile(bundle) as archive:
            members = archive.namelist()
            assert len(members) == len(set(members)) == len(raw_logs) + 2
            report = json.loads(archive.read("report.json"))
            assert report["schema_version"] == "1.0"
            names = set(report["extensions"]["log_files"])
            assert len(names) == len(raw_logs)
            assert {
                name.removeprefix("logs/") for name in members if name.startswith("logs/")
            } == names
            assert {item["source"] for item in report["extensions"]["timeline"]} == names
            for finding in report["findings"]:
                name = finding["resource"]["name"]
                assert name in names
                assert finding["resource"]["identifier"] == finding["evidence"]["location"] == name
                log = archive.read("logs/" + name).decode("utf-8")
                assert finding["evidence"]["summary"] == log.splitlines()[0]
            if report_format == "json":
                assert json.loads(rendered) == report
            surfaces.extend(members)
            surfaces.extend(archive.read(name).decode("utf-8") for name in members)
        assert all(secret not in surface for secret in secrets for surface in surfaces)


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
def test_shell_segments_never_reach_ci_exports(tmp_path: Path, report_format: str) -> None:
    source = tmp_path / "token='prefix'SYNTHETIC_P1_TARGET"
    source.mkdir()
    values = [
        'password="prefix"SYNTHETIC_P1_SUFFIX',
        "token='prefix'SYNTHETIC_P1_SINGLE",
        'password=prefix"SYNTHETIC_P1 MIDDLE"suffix',
        "token='first'\"SYNTHETIC_P1_SECOND\"SYNTHETIC_P1_THIRD",
        'password="prefix",SYNTHETIC_P1_COMMA',
        'password="prefix"$(printf SYNTHETIC_P1_SUBSTITUTION)',
        'token="prefix"`printf SYNTHETIC_P1_BACKTICK`',
    ]
    for index, value in enumerate(values):
        path = source / f"token='prefix'SYNTHETIC_P1_NAME{index}.log"
        path.write_text(
            f"tests failed {value}\nexit code 137\nordinary context\n",
            encoding="utf-8",
            newline="\n",
        )
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "run": {"name": values[0], "ordinary": [7, True, None]},
                "jobs": [{"id": 1, "name": values[1], "conclusion": "failure"}],
                "note": values[2],
            }
        ),
        encoding="utf-8",
    )
    for mode in ["stdout", "file"]:
        bundle = tmp_path / (mode + "-shell.zip")
        output = tmp_path / ("shell-report." + report_format)
        args = [
            sys.executable,
            "-m",
            "devops_toolkit",
            "ci-evidence",
            "--logs-dir",
            str(source),
            "--metadata",
            str(metadata),
            "--format",
            report_format,
            "--bundle",
            str(bundle),
            "--no-color",
        ]
        if mode == "file":
            args.extend(["--output", str(output)])
        result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=30)
        assert result.returncode == 1
        rendered = result.stdout if mode == "stdout" else output.read_text(encoding="utf-8")
        surfaces = [result.stdout, result.stderr, rendered]
        with zipfile.ZipFile(bundle) as archive:
            members = archive.namelist()
            assert len(members) == len(set(members)) == len(values) + 2
            surfaces.extend(members)
            surfaces.extend(archive.read(name).decode("utf-8") for name in members)
            report = json.loads(archive.read("report.json"))
            assert report["schema_version"] == "1.0"
            assert report["extensions"]["run"]["ordinary"] == [7, True, None]
            names = set(report["extensions"]["log_files"])
            assert len(names) == len(values)
            assert {item["source"] for item in report["extensions"]["timeline"]} == names
            for finding in report["findings"]:
                if finding["resource"]["type"] != "CILog":
                    continue
                name = finding["resource"]["name"]
                assert name == finding["resource"]["identifier"] == finding["evidence"]["location"]
                assert "logs/" + name in members
                assert finding["evidence"]["summary"] in archive.read("logs/" + name).decode(
                    "utf-8"
                )
            if report_format == "json":
                assert json.loads(rendered) == report
        assert all("SYNTHETIC_P1" not in surface for surface in surfaces)


@pytest.mark.integration
@pytest.mark.parametrize("report_format", ["console", "json", "markdown", "sarif"])
def test_provider_punctuation_never_reaches_cli_exports(
    punctuation_ci_inputs: tuple[Path, Path, dict[str, str], list[str]],
    tmp_path: Path,
    report_format: str,
) -> None:
    source, metadata, raw_logs, fragments = punctuation_ci_inputs
    for mode in ["stdout", "file"]:
        bundle = tmp_path / (mode + "-provider.zip")
        output = tmp_path / ("provider-report." + report_format)
        args = [
            sys.executable,
            "-m",
            "devops_toolkit",
            "ci-evidence",
            "--logs-dir",
            str(source),
            "--metadata",
            str(metadata),
            "--bundle",
            str(bundle),
            "--format",
            report_format,
            "--no-color",
        ]
        if mode == "file":
            args.extend(["--output", str(output)])
        result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=30)
        assert result.returncode == 1
        rendered = result.stdout if mode == "stdout" else output.read_text(encoding="utf-8")
        surfaces = [result.stdout, result.stderr, rendered]
        if report_format in {"json", "sarif"}:
            payload = json.loads(rendered)
            assert payload.get("schema_version", payload.get("version")) in {"1.0", "2.1.0"}
        with zipfile.ZipFile(bundle) as archive:
            members = archive.namelist()
            assert len(members) == len(set(members)) == len(raw_logs) + 2
            report = json.loads(archive.read("report.json"))
            assert report["schema_version"] == "1.0"
            assert report["extensions"]["run"]["ordinary"] == [7, True, None]
            names = set(report["extensions"]["log_files"])
            assert len(names) == len(raw_logs)
            assert {
                name.removeprefix("logs/") for name in members if name.startswith("logs/")
            } == names
            assert {item["source"] for item in report["extensions"]["timeline"]} == names
            for finding in report["findings"]:
                if finding["resource"]["type"] != "CILog":
                    continue
                name = finding["resource"]["name"]
                assert name == finding["resource"]["identifier"] == finding["evidence"]["location"]
                content = archive.read("logs/" + name).decode("utf-8")
                assert (
                    finding["evidence"]["summary"]
                    == content.splitlines()[finding["evidence"]["line"] - 1]
                )
            if report_format == "json":
                assert json.loads(rendered) == report
            surfaces.extend(members)
            surfaces.extend(archive.read(name).decode("utf-8") for name in members)
        assert all(fragment not in surface for fragment in fragments for surface in surfaces)
