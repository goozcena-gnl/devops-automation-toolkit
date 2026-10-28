from __future__ import annotations

import json
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from devops_toolkit.commands.ci_evidence import (
    _sanitize_logs,
    analyze_logs,
    build_report,
    write_bundle,
)
from devops_toolkit.core.models import Severity
from devops_toolkit.core.redaction import Redactor, fingerprint_sensitive
from devops_toolkit.reporters.dispatcher import ReportFormat, render_report


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    ("child", "parent"),
    [
        ("token=CANARY0 data/child.log", "token=CANARY1 data"),
        ("token=CANARY0 DATA/nested/child.log", "token=CANARY1 data"),
        ("ordinary/token=CANARY0 data/nested/child.log", "ordinary/token=CANARY1 data"),
        ("ordinary/Parent/child.log", "ordinary/parent"),
    ],
)
def test_ancestor_collisions_are_stable_and_archiveable(
    tmp_path: Path, child: str, parent: str, reverse: bool
) -> None:
    raw = {child: "tests failed child", parent: "tests failed parent"}
    raw["unchanged/nested/job.log"] = "tests failed ordinary"
    if reverse:
        raw = dict(reversed(list(raw.items())))
    safe = _sanitize_logs(raw)
    assert safe["unchanged/nested/job.log"] == raw["unchanged/nested/job.log"]
    assert len(safe) == len(raw)
    assert set(safe.values()) == set(raw.values())
    assert "CANARY" not in json.dumps(safe)
    assert _sanitize_logs(dict(reversed(list(raw.items())))) == safe
    for _ in range(3):
        assert _sanitize_logs(safe) == safe
        assert Redactor().redact_data(safe) == safe
    paths = [PureWindowsPath(name.lower()) for name in safe]
    assert len(set(paths)) == len(paths)
    assert all(other not in path.parents for path in paths for other in paths)
    for name in safe:
        for path_type in [PurePosixPath, PureWindowsPath]:
            assert not path_type(name).is_absolute()
            assert ".." not in path_type(name).parts
    source = tmp_path / "source"
    source.mkdir()
    (source / "ordinary.log").write_text("tests failed", encoding="utf-8")
    report, _, _ = build_report(logs_dir=source)
    findings, counts, timeline = analyze_logs(raw)
    report.findings = findings
    report.extensions.update(log_files=sorted(safe), signature_counts=counts, timeline=timeline)
    report = type(report).model_validate(report.as_dict())
    bundle = tmp_path / "ancestor.zip"
    write_bundle(bundle, report, raw, {})
    assert {finding.resource.name for finding in findings} == set(safe)
    assert {finding.resource.identifier for finding in findings} == set(safe)
    assert {finding.evidence.location for finding in findings} == set(safe)
    assert {item["source"] for item in timeline} == set(safe)
    with zipfile.ZipFile(bundle) as archive:
        assert json.loads(archive.read("report.json")) == report.as_dict()
        assert {name[5:] for name in archive.namelist() if name.startswith("logs/")} == set(safe)
        for name, content in safe.items():
            assert archive.read("logs/" + name).decode("utf-8") == content


def test_requested_ancestor_collision_bundle_reproduction(tmp_path: Path) -> None:
    source = tmp_path / "source"
    raw = {
        "token=CANARY0 data/child.log": "exit code 137 child",
        "token=CANARY1 data": "exit code 137 parent",
    }
    for name, content in raw.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    report, logs, metadata = build_report(logs_dir=source)
    write_bundle(tmp_path / "requested.zip", report, logs, metadata)


@pytest.mark.parametrize("reserved_tail", ["", "/child.log/nested.log"])
def test_ancestor_disambiguation_reserves_existing_digest_paths(reserved_tail: str) -> None:
    child = "token=CANARY1 data/child.log"
    digest = fingerprint_sensitive(child, namespace="ci-log-name").removeprefix("sha256:")
    reserved = f"{digest}.token=[REDACTED] data{reserved_tail}"
    raw = {
        "token=CANARY0 data": "tests failed parent",
        child: "tests failed child",
        reserved: "tests failed reserved",
    }
    safe = _sanitize_logs(raw)
    assert safe[reserved] == raw[reserved]
    assert len(safe) == len(raw)
    paths = [PureWindowsPath(name.casefold()) for name in safe]
    assert all(other not in path.parents for path in paths for other in paths)
    assert _sanitize_logs(safe) == safe
    assert _sanitize_logs(dict(reversed(list(raw.items())))) == safe


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


@pytest.mark.parametrize("count", [2, 3, 5])
@pytest.mark.parametrize("parent", ["", "ordinary/context/"])
def test_collision_names_are_stable_across_all_redaction_boundaries(
    count: int, parent: str
) -> None:
    logs = {
        f"{parent}password=CANARY{index}.log": f"tests failed job {index}" for index in range(count)
    }
    safe = _sanitize_logs(logs)
    assert len(safe) == count
    assert set(safe.values()) == set(logs.values())
    assert "CANARY" not in json.dumps(safe)
    for name in safe:
        assert Redactor().redact(name) == name
        for path_type in [PurePosixPath, PureWindowsPath]:
            assert not path_type(name).is_absolute()
            assert ".." not in path_type(name).parts
    repeated_logs = safe
    for _ in range(3):
        repeated_logs = _sanitize_logs(Redactor().redact_data(repeated_logs))
        assert repeated_logs == safe
    assert _sanitize_logs(dict(reversed(list(logs.items())))) == safe
    findings, _, timeline = analyze_logs(logs)
    repeated, _, _ = analyze_logs(safe)
    assert {finding.resource.name for finding in findings} == set(safe)
    assert {item["source"] for item in timeline} == set(safe)
    assert {finding.fingerprint for finding in repeated} == {
        finding.fingerprint for finding in findings
    }


def test_collision_names_reserve_existing_safe_names() -> None:
    digest = fingerprint_sensitive("password=CANARY1.log", namespace="ci-log-name").removeprefix(
        "sha256:"
    )
    reserved = f"{digest}.password=[REDACTED]"
    logs = {
        "password=CANARY0.log": "tests failed zero",
        "password=CANARY1.log": "tests failed one",
        "password=[REDACTED]": "tests failed existing safe name",
        reserved: "tests failed existing digest name",
        "ordinary/job.log": "tests failed ordinary",
    }
    safe = _sanitize_logs(logs)
    assert len(safe) == len(logs)
    assert set(safe.values()) == set(logs.values())
    for name in ["password=[REDACTED]", reserved, "ordinary/job.log"]:
        assert safe[name] == logs[name]
    assert _sanitize_logs(safe) == safe


def test_collision_names_handle_repeated_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "devops_toolkit.commands.ci_evidence.fingerprint_sensitive",
        lambda *args, **kwargs: "sha256:abc",
    )
    logs = {f"token=CANARY{index}.log": f"tests failed {index}" for index in range(5)}
    safe = _sanitize_logs(logs)
    assert len(safe) == len(logs)
    assert set(safe.values()) == set(logs.values())
    assert _sanitize_logs(safe) == safe
    assert Redactor().redact_data(safe) == safe


def test_collision_names_preserve_ordinary_paths_and_fingerprints() -> None:
    logs = {
        "ordinary/job one.log": "tests failed ordinary",
        "nested/job-two.log": "tests failed other",
    }
    assert _sanitize_logs(logs) == logs
    before, _, _ = analyze_logs(logs)
    after, _, _ = analyze_logs(_sanitize_logs(_sanitize_logs(logs)))
    assert [finding.fingerprint for finding in before] == [finding.fingerprint for finding in after]


def test_collision_names_are_unique_on_case_insensitive_filesystems() -> None:
    logs = {
        "ordinary/Password=CANARY0.log": "tests failed zero",
        "ordinary/password=CANARY1.log": "tests failed one",
        "ordinary/PASSWORD=CANARY2.log": "tests failed two",
    }
    safe = _sanitize_logs(logs)
    assert len({str(PureWindowsPath(name)).casefold() for name in safe}) == len(logs)
    assert _sanitize_logs(safe) == safe


@pytest.mark.parametrize(
    "unsafe", ["../outside.log", "nested/../../outside.log", "token=CANARY/../../outside.log"]
)
def test_collision_names_do_not_bypass_archive_path_guards(tmp_path: Path, unsafe: str) -> None:
    source = tmp_path / "logs"
    source.mkdir()
    (source / "ordinary.log").write_text("tests failed ordinary", encoding="utf-8")
    report, _, _ = build_report(logs_dir=source)
    logs = {"password=CANARY0.log": "tests failed zero", "password=CANARY1.log": "tests failed one"}
    logs[unsafe] = "must not be archived"
    bundle = tmp_path / "safe.zip"
    write_bundle(bundle, report, logs, {})
    with zipfile.ZipFile(bundle) as archive:
        members = [name for name in archive.namelist() if name.startswith("logs/")]
        assert len(members) == 2
        assert all(".." not in PurePosixPath(name).parts for name in members)
        assert {archive.read(name).decode("utf-8") for name in members} == {
            "tests failed zero",
            "tests failed one",
        }
    assert not (tmp_path / "outside.log").exists()


def test_quoted_key_filename_collisions_keep_stable_direct_references() -> None:
    # Direct callers may supply POSIX names that cannot be created on Windows.
    raw = {
        f"'password':prefix;CANARY_{index}.log": f"tests failed job {index}" for index in range(3)
    }
    safe = _sanitize_logs(raw)
    assert len(safe) == len(raw)
    assert "CANARY" not in json.dumps(safe)
    assert _sanitize_logs(safe) == safe
    assert Redactor().redact_data(safe) == safe
    assert _sanitize_logs(dict(reversed(list(raw.items())))) == safe
    findings, _, timeline = analyze_logs(safe)
    assert {finding.resource.name for finding in findings} == set(safe)
    assert {finding.evidence.location for finding in findings} == set(safe)
    assert {item["source"] for item in timeline} == set(safe)


def test_malformed_json_names_keep_collision_and_evidence_references() -> None:
    # Direct provider callers can return names that Windows cannot create locally.
    raw = {
        f'"password":"CANARY_HEAD_{index}",CANARY_TAIL_{index}': f"tests failed job {index}"
        for index in range(3)
    }
    safe = _sanitize_logs(raw)
    assert len(safe) == len(raw)
    assert "CANARY" not in json.dumps(safe)
    assert _sanitize_logs(safe) == safe
    assert Redactor().redact_data(safe) == safe
    assert len({name.casefold() for name in safe}) == len(raw)
    findings, _, timeline = analyze_logs(safe)
    assert {finding.resource.name for finding in findings} == set(safe)
    assert {finding.evidence.location for finding in findings} == set(safe)
    assert {item["source"] for item in timeline} == set(safe)
