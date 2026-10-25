from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from devops_toolkit.commands.ci_evidence import analyze_logs, build_report, write_bundle
from devops_toolkit.core.models import Severity
from devops_toolkit.reporters.dispatcher import ReportFormat, render_report


def test_ci_log_analysis_deduplicates_and_classifies() -> None:
    findings, counts, timeline = analyze_logs(
        {"job.log": "tests failed\ntests failed\nexit code 137"}
    )
    assert {finding.id for finding in findings} == {"CI-TEST-FAILURE", "CI-OUT-OF-MEMORY"}
    assert counts["CI-TEST-FAILURE"] == 2
    assert timeline


def test_ci_evidence_redacts_bundle(repository_root: Path, tmp_path: Path) -> None:
    fixture = repository_root / "tests/fixtures/ci-logs"
    report, logs, metadata = build_report(
        logs_dir=fixture,
        metadata_path=fixture / "metadata.json",
        threshold=Severity.HIGH,
    )
    assert report.status.value == "fail"
    assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in "\n".join(logs.values())
    bundle = tmp_path / "ci-evidence.zip"
    write_bundle(bundle, report, logs, metadata)
    assert bundle.exists()


@pytest.mark.parametrize("report_format", list(ReportFormat))
def test_structured_credentials_never_reach_reports_or_bundle(
    structured_ci_inputs: tuple[Path, Path, list[str]], tmp_path: Path, report_format: ReportFormat
) -> None:
    logs_dir, metadata_path, secrets = structured_ci_inputs
    report, logs, metadata = build_report(logs_dir=logs_dir, metadata_path=metadata_path)
    rendered = render_report(report, report_format, color=False)
    assert report.status.value == "fail"
    assert report.schema_version == "1.0"
    assert report.extensions["run"]["ordinary"] == {"count": 7}
    assert "keep log context" in logs["job.log"]
    assert report.extensions["signature_counts"] == {"CI-TEST-FAILURE": 1}
    bundle = tmp_path / "evidence.zip"
    write_bundle(bundle, report, logs, metadata)
    surfaces = [rendered, report.model_dump_json(), json.dumps(metadata), *logs.values()]
    with zipfile.ZipFile(bundle) as archive:
        surfaces.extend(archive.namelist())
        surfaces.extend(archive.read(name).decode("utf-8") for name in archive.namelist())
        assert json.loads(archive.read("report.json"))["schema_version"] == "1.0"
        assert json.loads(archive.read("metadata.json"))["run"]["id"] == 123
    for secret in secrets:
        assert all(secret.split()[0] not in surface for surface in surfaces)


def test_direct_analysis_and_bundle_inputs_are_sanitized(tmp_path: Path) -> None:
    marker = "SYNTHETIC_DIRECT_B02"
    filename = f"password={marker}.log"
    raw_logs = {filename: 'tests failed {"password": "' + marker + '"}'}
    findings, _, timeline = analyze_logs(raw_logs)
    assert marker not in json.dumps([finding.model_dump(mode="json") for finding in findings])
    assert marker not in json.dumps(timeline)
    source = tmp_path / "logs"
    source.mkdir()
    (source / "normal.log").write_text("tests failed", encoding="utf-8")
    report, _, _ = build_report(logs_dir=source)
    report.extensions["run"] = {"token": marker}
    bundle = tmp_path / "direct.zip"
    write_bundle(bundle, report, raw_logs, {"client_secret": marker})
    with zipfile.ZipFile(bundle) as archive:
        assert marker not in "\n".join(archive.namelist())
        assert all(marker.encode() not in archive.read(name) for name in archive.namelist())


def test_redacted_log_names_do_not_overwrite_each_other(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    for index in range(2):
        (logs / f"password=SYNTHETIC_{index}.log").write_text(
            f"tests failed job {index}", encoding="utf-8"
        )
    report, collected, _ = build_report(logs_dir=logs)
    assert len(collected) == 2
    assert len(report.findings) == 2
    assert set(collected.values()) == {"tests failed job 0", "tests failed job 1"}
    assert "SYNTHETIC_" not in "\n".join(collected)
    assert len({finding.fingerprint for finding in report.findings}) == 2


def test_multiline_redaction_preserves_original_evidence_locations() -> None:
    findings, _, timeline = analyze_logs(
        {"job.log": '{"password": {\n "nested": "synthetic"\n}}\ntests failed'}
    )
    assert findings[0].evidence.line == 4
    assert timeline[0]["line"] == 4


@pytest.mark.parametrize(
    ("key", "marker"), [("password", "SYNTHETIC_B02_PATH"), ("token", "SYNTHETIC_B02_TOKEN")]
)
def test_log_directory_target_never_contains_credentials(
    tmp_path: Path, key: str, marker: str
) -> None:
    source = tmp_path / f"{key}={marker}" / "logs"
    source.mkdir(parents=True)
    (source / "job.log").write_text(
        "exit code 137\nordinary context\n", encoding="utf-8", newline="\n"
    )
    report, logs, _ = build_report(logs_dir=source)
    assert marker not in report.metadata.target
    assert "[REDACTED]" in report.metadata.target
    assert report.schema_version == "1.0"
    assert report.status.value == "fail"
    assert logs == {"job.log": "exit code 137\nordinary context\n"}
    assert report.findings[0].evidence.line == 1


def test_log_directory_target_preserves_ordinary_absolute_paths(tmp_path: Path) -> None:
    source = tmp_path / "ordinary logs" / "nested"
    source.mkdir(parents=True)
    (source / "job.log").write_text("ordinary successful job\n", encoding="utf-8", newline="\n")
    report, logs, _ = build_report(logs_dir=source)
    assert report.metadata.target == str(source.resolve())
    assert report.schema_version == "1.0"
    assert report.status.value == "pass"
    assert report.findings == []
    assert logs == {"job.log": "ordinary successful job\n"}
