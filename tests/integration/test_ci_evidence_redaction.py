from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


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
