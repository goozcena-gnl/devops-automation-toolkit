from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from devops_toolkit.commands.ci_evidence import build_report, write_bundle


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
