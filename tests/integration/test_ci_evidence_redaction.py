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
