from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from devops_toolkit.commands.ci_evidence import analyze_logs, build_report, write_bundle
from devops_toolkit.core.redaction import Redactor
from devops_toolkit.reporters.dispatcher import ReportFormat, render_report


def test_json_string_path_metadata_is_safe_on_every_export(tmp_path: Path) -> None:
    path = "ordinary/token=CANARY_HEAD CANARY_TAIL/job.log"
    raw = {
        "log_path": path,
        "run": {
            "log_path": path,
            "nested": [{"artifact_paths": [path, r"C:\token=CANARY_HEAD CANARY_TAIL\job.log"]}],
            "ordinary": {"count": 7, "message": "tests failed; count=7"},
        },
    }
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(json.dumps(raw), encoding="utf-8")
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "job.log").write_text("exit code 137\n", encoding="utf-8")
    report, logs, metadata = build_report(logs_dir=logs_dir, metadata_path=metadata_path)
    surfaces = [
        str(Redactor().redact_data({"log_path": path})),
        json.dumps(metadata),
        report.model_dump_json(),
    ]
    surfaces.extend(render_report(report, fmt, color=False) for fmt in ReportFormat)
    assert report.extensions["run"] == metadata["run"]
    assert metadata["run"]["ordinary"] == raw["run"]["ordinary"]
    bundle = tmp_path / "string-paths.zip"
    # Pass raw metadata to exercise the archive's independent final boundary.
    write_bundle(bundle, report, logs, raw)
    with zipfile.ZipFile(bundle) as archive:
        bundled = json.loads(archive.read("report.json"))
        assert bundled == report.as_dict()
        assert json.loads(archive.read("metadata.json")) == metadata
        surfaces.extend(archive.read(name).decode("utf-8") for name in archive.namelist())
    assert all(
        fragment not in surface
        for fragment in ["CANARY_HEAD", "CANARY_TAIL"]
        for surface in surfaces
    )


@pytest.mark.parametrize("provider", [False, True])
def test_latest_metadata_and_path_boundaries_preserve_export_contracts(
    repository_root: Path,
    latest_ci_inputs: tuple[Path, Path, dict[str, str], list[str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider: bool,
) -> None:
    source, metadata_path, raw, fragments = latest_ci_inputs
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if provider:
        metadata["diagnostics"] = (
            Path("ordinary") / "token=CANARY_HEAD CANARY_TAIL",
            {"nested": ["password=CANARY_HEAD"]},
        )
        monkeypatch.setattr(
            "devops_toolkit.commands.ci_evidence._collect_github_metadata",
            lambda *args: metadata,
        )

        def download(repository: str, run_id: int, destination: Path, timeout: int) -> None:
            with zipfile.ZipFile(destination, "w") as archive:
                for name, content in raw.items():
                    archive.writestr(name, content)

        monkeypatch.setattr("devops_toolkit.commands.ci_evidence._download_github_logs", download)
        report, logs, safe_metadata = build_report(repository="synthetic/repository", run_id=7)
    else:
        report, logs, safe_metadata = build_report(logs_dir=source, metadata_path=metadata_path)
    assert report.schema_version == "1.0"
    assert report.status.value == "fail"
    assert report.metadata.partial is False
    assert sorted(
        item["code"] for item in safe_metadata["run"].values() if isinstance(item, dict)
    ) == [1, 7, 137]
    assert safe_metadata["run"]["ordinary"] == [7, True, None]
    assert report.extensions["run"] == safe_metadata["run"]
    names = set(logs)
    assert len(names) == len(raw)
    assert set(report.extensions["log_files"]) == names
    assert {item["source"] for item in report.extensions["timeline"]} == names
    for finding in report.findings:
        if finding.resource.type == "CILog":
            name = finding.resource.name
            assert name == finding.resource.identifier == finding.evidence.location
            assert name in names
            assert finding.evidence.summary == logs[name].splitlines()[finding.evidence.line - 1]
    assert Redactor().redact_data(report.as_dict()) == report.as_dict()
    schema_dir = repository_root / "configs/schemas"
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text())
    registry = Registry().with_resource(
        "finding.schema.json", Resource.from_contents(finding_schema)
    )
    validator = Draft202012Validator(
        json.loads((schema_dir / "report.schema.json").read_text()), registry=registry
    )
    validator.validate(report.as_dict())
    bundle = tmp_path / "latest-contract.zip"
    write_bundle(bundle, report, raw, metadata)
    surfaces = [report.model_dump_json(), json.dumps(safe_metadata), *logs, *logs.values()]
    surfaces.extend(render_report(report, fmt, color=False) for fmt in ReportFormat)
    with zipfile.ZipFile(bundle) as archive:
        members = archive.namelist()
        assert len(members) == len(set(members)) == len(raw) + 2
        assert {name[5:] for name in members if name.startswith("logs/")} == names
        bundled = json.loads(archive.read("report.json"))
        validator.validate(bundled)
        assert bundled == report.as_dict()
        assert json.loads(archive.read("metadata.json")) == safe_metadata
        surfaces.extend(members)
        surfaces.extend(archive.read(name).decode("utf-8") for name in members)
    assert all(fragment not in surface for fragment in fragments for surface in surfaces)


def test_redacted_report_and_archive_preserve_schema_contract(
    repository_root: Path, structured_ci_inputs: tuple[Path, Path, list[str]], tmp_path: Path
) -> None:
    schema_dir = repository_root / "configs/schemas"
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text())
    resource = Resource.from_contents(finding_schema)
    registry = (
        Registry()
        .with_resource("finding.schema.json", resource)
        .with_resource(finding_schema["$id"], resource)
    )
    validator = Draft202012Validator(
        json.loads((schema_dir / "report.schema.json").read_text()), registry=registry
    )
    logs_dir, metadata_path, _ = structured_ci_inputs
    report, logs, metadata = build_report(logs_dir=logs_dir, metadata_path=metadata_path)
    validator.validate(report.as_dict())
    bundle = tmp_path / "contract.zip"
    write_bundle(bundle, report, logs, metadata)
    with zipfile.ZipFile(bundle) as archive:
        validator.validate(json.loads(archive.read("report.json")))
        safe_metadata = json.loads(archive.read("metadata.json"))
        assert safe_metadata["run"]["ordinary"] == {"count": 7}
        assert safe_metadata["credentials"] == {
            "password": "[REDACTED]",
            "client_secret": "[REDACTED]",
        }


def test_benign_ci_finding_fingerprints_remain_compatible(repository_root: Path) -> None:
    logs_dir = repository_root / "tests/fixtures/ci-logs"
    report, _, _ = build_report(logs_dir=logs_dir, metadata_path=logs_dir / "metadata.json")
    example = json.loads((repository_root / "examples/reports/phase5/ci-evidence.json").read_text())
    assert {finding.id: finding.fingerprint for finding in report.findings} == {
        finding["id"]: finding["fingerprint"] for finding in example["findings"]
    }
    assert report.status.value == example["status"] == "fail"


@pytest.mark.parametrize(
    ("key", "marker"), [("password", "SYNTHETIC_B02_PATH"), ("token", "SYNTHETIC_B02_TOKEN")]
)
def test_log_directory_target_preserves_report_schema_and_bundle(
    repository_root: Path, tmp_path: Path, key: str, marker: str
) -> None:
    source = tmp_path / f"{key}={marker}" / "logs"
    source.mkdir(parents=True)
    (source / "job.log").write_text("exit code 137\n", encoding="utf-8")
    schema_dir = repository_root / "configs/schemas"
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text())
    resource = Resource.from_contents(finding_schema)
    registry = (
        Registry()
        .with_resource("finding.schema.json", resource)
        .with_resource(finding_schema["$id"], resource)
    )
    validator = Draft202012Validator(
        json.loads((schema_dir / "report.schema.json").read_text()), registry=registry
    )
    report, logs, metadata = build_report(logs_dir=source)
    validator.validate(report.as_dict())
    bundle = tmp_path / "target.zip"
    write_bundle(bundle, report, logs, metadata)
    with zipfile.ZipFile(bundle) as archive:
        bundled = json.loads(archive.read("report.json"))
        validator.validate(bundled)
        assert marker not in bundled["metadata"]["target"]
    assert marker not in report.metadata.target
    assert report.status.value == "fail"


@pytest.mark.parametrize("direct", [False, True])
def test_collision_evidence_references_match_archived_logs(
    repository_root: Path,
    collision_ci_inputs: tuple[Path, Path, dict[str, str], list[str]],
    tmp_path: Path,
    direct: bool,
) -> None:
    source, metadata_path, raw_logs, secrets = collision_ci_inputs
    report, logs, metadata = build_report(logs_dir=source, metadata_path=metadata_path)
    if direct:
        findings, counts, timeline = analyze_logs(raw_logs)
        report.findings = findings
        report.extensions.update(signature_counts=counts, timeline=timeline)
    names = set(report.extensions["log_files"])
    assert len(names) == len(raw_logs)
    assert set(logs) == names
    assert {finding.resource.name for finding in report.findings} == names
    assert {finding.resource.identifier for finding in report.findings} == names
    assert {finding.evidence.location for finding in report.findings} == names
    assert {item["source"] for item in report.extensions["timeline"]} == names
    safe = Redactor().redact_data(report.as_dict())
    assert safe == report.as_dict()
    schema_dir = repository_root / "configs/schemas"
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text())
    registry = Registry().with_resource(
        "finding.schema.json", Resource.from_contents(finding_schema)
    )
    validator = Draft202012Validator(
        json.loads((schema_dir / "report.schema.json").read_text()), registry=registry
    )
    validator.validate(safe)
    bundle = tmp_path / "collisions.zip"
    archive_logs = raw_logs if direct else logs
    write_bundle(bundle, report, archive_logs, metadata)
    with zipfile.ZipFile(bundle) as archive:
        members = archive.namelist()
        assert len(members) == len(set(members)) == len(raw_logs) + 2
        assert {name.removeprefix("logs/") for name in members if name.startswith("logs/")} == names
        bundled = json.loads(archive.read("report.json"))
        validator.validate(bundled)
        assert bundled == report.as_dict()
        assert json.loads(archive.read("metadata.json"))["run"] == {
            "token": "[REDACTED]",
            "ordinary": 7,
        }
        for finding in report.findings:
            name = finding.resource.name
            assert archive.read("logs/" + name).decode("utf-8") == logs[name]
            assert finding.evidence.summary == logs[name].splitlines()[0]
        surfaces = [*members, *(archive.read(name).decode("utf-8") for name in members)]
    surfaces.extend(render_report(report, fmt, color=False) for fmt in ReportFormat)
    assert all(secret not in surface for secret in secrets for surface in surfaces)


def test_shell_segments_keep_schema_and_evidence_locations(
    repository_root: Path, tmp_path: Path
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    text = 'password="prefix\nSYNTHETIC_P1_MIDDLE"SYNTHETIC_P1_SUFFIX\nexit code 137\n'
    (logs_dir / "ordinary.log").write_text(text, encoding="utf-8", newline="\n")
    report, logs, metadata = build_report(logs_dir=logs_dir)
    schema_dir = repository_root / "configs/schemas"
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text())
    registry = Registry().with_resource(
        "finding.schema.json", Resource.from_contents(finding_schema)
    )
    validator = Draft202012Validator(
        json.loads((schema_dir / "report.schema.json").read_text()), registry=registry
    )
    validator.validate(report.as_dict())
    assert report.findings[0].evidence.line == 3
    assert report.extensions["timeline"][0]["line"] == 3
    assert "SYNTHETIC_P1" not in report.model_dump_json()
    assert "SYNTHETIC_P1" not in logs["ordinary.log"]
    assert logs["ordinary.log"].count("\n") == text.count("\n")
    bundle = tmp_path / "shell-contract.zip"
    write_bundle(bundle, report, logs, metadata)
    with zipfile.ZipFile(bundle) as archive:
        bundled = json.loads(archive.read("report.json"))
        validator.validate(bundled)
        assert bundled == report.as_dict()
        assert "SYNTHETIC_P1" not in archive.read("logs/ordinary.log").decode("utf-8")


@pytest.mark.parametrize("direct", [False, True])
def test_provider_punctuation_preserves_export_contracts(
    repository_root: Path,
    punctuation_ci_inputs: tuple[Path, Path, dict[str, str], list[str]],
    tmp_path: Path,
    direct: bool,
) -> None:
    source, metadata_path, raw_logs, fragments = punctuation_ci_inputs
    report, logs, metadata = build_report(logs_dir=source, metadata_path=metadata_path)
    if direct:
        findings, counts, timeline = analyze_logs(raw_logs)
        report.findings = findings
        report.extensions.update(signature_counts=counts, timeline=timeline)
        report = type(report).model_validate(report.as_dict())
    redactor = Redactor()
    assert redactor.redact_data(report.as_dict()) == report.as_dict()
    assert redactor.redact_data(logs) == logs
    names = set(logs)
    assert names == set(report.extensions["log_files"])
    assert len(names) == len(raw_logs)
    assert {item["source"] for item in report.extensions["timeline"]} == names
    for finding in report.findings:
        if finding.resource.type != "CILog":
            continue
        name = finding.resource.name
        assert name == finding.resource.identifier == finding.evidence.location
        assert finding.evidence.summary == logs[name].splitlines()[finding.evidence.line - 1]
    assert {content.count("\n") for content in logs.values()} == {
        content.count("\n") for content in raw_logs.values()
    }
    schema_dir = repository_root / "configs/schemas"
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text())
    registry = Registry().with_resource(
        "finding.schema.json", Resource.from_contents(finding_schema)
    )
    validator = Draft202012Validator(
        json.loads((schema_dir / "report.schema.json").read_text()), registry=registry
    )
    validator.validate(report.as_dict())
    assert report.schema_version == "1.0"
    assert report.status.value == "fail"
    assert report.extensions["run"]["ordinary"] == [7, True, None]
    bundle = tmp_path / "provider-punctuation.zip"
    write_bundle(bundle, report, raw_logs if direct else logs, metadata)
    surfaces = [report.model_dump_json(), json.dumps(metadata), *logs, *logs.values()]
    surfaces.extend(render_report(report, fmt, color=False) for fmt in ReportFormat)
    with zipfile.ZipFile(bundle) as archive:
        members = archive.namelist()
        assert len(members) == len(set(members)) == len(raw_logs) + 2
        assert {name.removeprefix("logs/") for name in members if name.startswith("logs/")} == names
        bundled = json.loads(archive.read("report.json"))
        validator.validate(bundled)
        assert bundled == report.as_dict()
        for name in names:
            assert archive.read("logs/" + name).decode("utf-8") == logs[name]
        surfaces.extend(members)
        surfaces.extend(archive.read(name).decode("utf-8") for name in members)
    assert all(fragment not in surface for fragment in fragments for surface in surfaces)
