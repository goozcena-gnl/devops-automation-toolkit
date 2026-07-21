"""Sanitized deterministic CI failure evidence collector."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from devops_toolkit.core.exceptions import (
    CommandExecutionError,
    ConfigurationError,
    DependencyUnavailableError,
)
from devops_toolkit.core.filesystem import atomic_write_text
from devops_toolkit.core.models import (
    Confidence,
    Evidence,
    Finding,
    Report,
    ReportMetadata,
    ResourceRef,
    Severity,
    utc_now,
)
from devops_toolkit.core.redaction import Redactor
from devops_toolkit.core.subprocess import executable_path, run_command
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.reporters.json_report import render_json
from devops_toolkit.version import __version__

TOOL_NAME = "ci-evidence"
SIGNATURES: tuple[tuple[str, Severity, re.Pattern[str], str], ...] = (
    (
        "CI-OUT-OF-MEMORY",
        Severity.CRITICAL,
        re.compile(r"(?:out of memory|oomkilled|killed process .* memory|exit code 137)", re.I),
        "Increase memory capacity or reduce job concurrency and memory pressure.",
    ),
    (
        "CI-DISK-EXHAUSTION",
        Severity.HIGH,
        re.compile(r"(?:no space left on device|disk quota exceeded)", re.I),
        "Clean caches and artifacts or increase runner disk capacity.",
    ),
    (
        "CI-PERMISSION-DENIED",
        Severity.HIGH,
        re.compile(
            r"(?:permission denied|resource not accessible by integration|http 403|status 403)",
            re.I,
        ),
        "Review workflow permissions, token scopes, filesystem ownership, and protected-environment policy.",
    ),
    (
        "CI-AUTHENTICATION-FAILED",
        Severity.HIGH,
        re.compile(
            r"(?:authentication failed|unauthorized|http 401|status 401|invalid token)", re.I
        ),
        "Rotate affected credentials and validate OIDC or token configuration without printing secret values.",
    ),
    (
        "CI-TIMEOUT",
        Severity.HIGH,
        re.compile(r"(?:timed out|timeout exceeded|job was cancelled because it exceeded)", re.I),
        "Identify the slow step, bound retries, and set realistic job and command timeouts.",
    ),
    (
        "CI-NETWORK-FAILURE",
        Severity.MEDIUM,
        re.compile(
            r"(?:connection reset|connection refused|temporary failure in name resolution|could not resolve host|tls handshake timeout)",
            re.I,
        ),
        "Check DNS, egress, proxy, registry availability, and retry only safe idempotent operations.",
    ),
    (
        "CI-DEPENDENCY-FAILURE",
        Severity.MEDIUM,
        re.compile(
            r"(?:dependency resolution failed|no matching distribution found|package .* not found|could not resolve dependencies)",
            re.I,
        ),
        "Pin dependencies, verify repositories, and preserve the failing resolver evidence.",
    ),
    (
        "CI-TEST-FAILURE",
        Severity.MEDIUM,
        re.compile(r"(?:tests? failed|failures?=\d+|assertionerror|\bfailed\b.*\bpassed\b)", re.I),
        "Inspect the first causal test failure and reproduce it with the same dependency and environment inputs.",
    ),
)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read CI metadata JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("CI metadata root must be an object")
    return payload


def _safe_environment() -> dict[str, str]:
    allowed = {
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_HOST",
        "XDG_CONFIG_HOME",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def _download_github_logs(repository: str, run_id: int, destination: Path, timeout: int) -> None:
    gh = executable_path("gh")
    if gh is None:
        raise DependencyUnavailableError("Required executable is unavailable: gh")
    endpoint = f"repos/{repository}/actions/runs/{run_id}/logs"
    try:
        completed = subprocess.run(  # noqa: S603
            [gh, "api", endpoint],
            capture_output=True,
            check=False,
            timeout=timeout,
            shell=False,
            env=_safe_environment(),
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError("Timed out while downloading GitHub Actions logs") from exc
    if completed.returncode != 0:
        detail = Redactor().redact(completed.stderr.decode("utf-8", errors="replace"))
        raise CommandExecutionError(f"Unable to download GitHub Actions logs: {detail[:1000]}")
    destination.write_bytes(completed.stdout)


def _collect_github_metadata(repository: str, run_id: int, timeout: int) -> dict[str, Any]:
    if executable_path("gh") is None:
        raise DependencyUnavailableError("Required executable is unavailable: gh")
    run_result = run_command(
        ["gh", "api", f"repos/{repository}/actions/runs/{run_id}"],
        timeout_seconds=timeout,
        max_output_chars=500_000,
        sanitize_output=True,
    )
    jobs_result = run_command(
        ["gh", "api", f"repos/{repository}/actions/runs/{run_id}/jobs?filter=all&per_page=100"],
        timeout_seconds=timeout,
        max_output_chars=2_000_000,
        sanitize_output=True,
    )
    if not run_result.succeeded or not jobs_result.succeeded:
        detail = run_result.stderr or jobs_result.stderr or "GitHub API request failed"
        raise CommandExecutionError(f"Unable to collect GitHub Actions metadata: {detail[:1000]}")
    try:
        run_payload = json.loads(run_result.stdout)
        jobs_payload = json.loads(jobs_result.stdout)
    except json.JSONDecodeError as exc:
        raise CommandExecutionError(f"GitHub API returned invalid JSON: {exc}") from exc
    return {"run": run_payload, "jobs": jobs_payload.get("jobs", [])}


def _extract_zip(source: Path, destination: Path, *, max_total_bytes: int) -> None:
    try:
        with zipfile.ZipFile(source) as archive:
            total = 0
            for info in archive.infolist():
                if info.is_dir():
                    continue
                total += info.file_size
                if total > max_total_bytes:
                    raise ConfigurationError("CI log archive exceeds configured extraction limit")
                resolved = (destination / info.filename).resolve()
                if destination.resolve() not in resolved.parents:
                    raise ConfigurationError("CI log archive contains an unsafe path")
                resolved.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source_handle, resolved.open("wb") as target_handle:
                    target_handle.write(source_handle.read())
    except zipfile.BadZipFile as exc:
        raise ConfigurationError(f"Downloaded CI logs are not a valid ZIP archive: {exc}") from exc


def _collect_log_files(root: Path, *, max_file_bytes: int, max_total_bytes: int) -> dict[str, str]:
    redactor = Redactor()
    collected: dict[str, str] = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        size = path.stat().st_size
        remaining = max_total_bytes - total
        if remaining <= 0:
            break
        read_size = min(size, max_file_bytes, remaining)
        with path.open("rb") as handle:
            raw = handle.read(read_size)
        text = raw.decode("utf-8", errors="replace")
        if read_size < size:
            text += "\n[LOG TRUNCATED BY DEVOPS TOOLKIT]"
        relative = path.relative_to(root).as_posix()
        collected[relative] = redactor.redact(text)
        total += read_size
    return collected


def analyze_logs(
    logs: dict[str, str],
) -> tuple[list[Finding], dict[str, int], list[dict[str, Any]]]:
    findings: list[Finding] = []
    counts: Counter[str] = Counter()
    timeline: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for filename, content in logs.items():
        lines = content.splitlines()
        for line_number, line in enumerate(lines, start=1):
            for identifier, severity, pattern, recommendation in SIGNATURES:
                if not pattern.search(line):
                    continue
                dedupe = (identifier, filename)
                counts[identifier] += 1
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                excerpt = line.strip()[:500]
                findings.append(
                    Finding(
                        id=identifier,
                        tool=TOOL_NAME,
                        category="ci-failure",
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        title=identifier.removeprefix("CI-").replace("-", " ").title(),
                        description="A deterministic log signature matched a known CI failure category; it is evidence, not a confirmed root cause.",
                        recommendation=recommendation,
                        resource=ResourceRef(type="CILog", name=filename, identifier=filename),
                        evidence=Evidence(summary=excerpt, location=filename, line=line_number),
                    )
                )
                timeline.append(
                    {
                        "source": filename,
                        "line": line_number,
                        "category": identifier,
                        "excerpt": excerpt,
                    }
                )
    return findings, dict(counts), timeline[:200]


def _job_findings(metadata: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    jobs = metadata.get("jobs", [])
    if not isinstance(jobs, list):
        return findings
    for job in jobs:
        if not isinstance(job, dict):
            continue
        conclusion = str(job.get("conclusion", ""))
        if conclusion not in {"failure", "timed_out", "cancelled", "action_required"}:
            continue
        name = str(job.get("name", job.get("id", "unknown-job")))
        steps = job.get("steps", [])
        failed_steps = (
            [
                str(step.get("name", "unknown-step"))
                for step in steps
                if isinstance(step, dict)
                and str(step.get("conclusion", "")) in {"failure", "timed_out", "cancelled"}
            ]
            if isinstance(steps, list)
            else []
        )
        findings.append(
            Finding(
                id="CI-JOB-FAILED",
                tool=TOOL_NAME,
                category="ci-failure",
                severity=Severity.HIGH
                if conclusion in {"failure", "timed_out"}
                else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title=f"CI job failed: {name}",
                recommendation="Inspect the first failed step and correlate it with the sanitized log signatures.",
                resource=ResourceRef(type="CIJob", name=name, identifier=str(job.get("id", name))),
                evidence=Evidence(
                    summary=f"conclusion={conclusion}; failed_steps={failed_steps or ['unknown']}"
                ),
            )
        )
    return findings


def write_bundle(
    destination: Path, report: Report, logs: dict[str, str], metadata: dict[str, Any]
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="devops-toolkit-ci-bundle-") as temp_dir:
        root = Path(temp_dir)
        atomic_write_text(root / "report.json", render_json(report))
        safe_metadata = Redactor().redact(json.dumps(metadata, indent=2, default=str))
        atomic_write_text(root / "metadata.json", safe_metadata + "\n")
        logs_root = root / "logs"
        for filename, content in logs.items():
            safe_name = Path(filename)
            if safe_name.is_absolute() or ".." in safe_name.parts:
                continue
            atomic_write_text(logs_root / safe_name, content)
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(root).as_posix())


def build_report(
    *,
    logs_dir: Path | None = None,
    metadata_path: Path | None = None,
    repository: str | None = None,
    run_id: int | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 120,
    max_file_bytes: int = 2_000_000,
    max_total_bytes: int = 25_000_000,
) -> tuple[Report, dict[str, str], dict[str, Any]]:
    started = utc_now()
    metadata = _read_json(metadata_path) if metadata_path else {}
    temp: tempfile.TemporaryDirectory[str] | None = None
    try:
        if logs_dir is None:
            if repository is None or run_id is None:
                raise ConfigurationError(
                    "Provide --logs-dir for offline analysis or both --repository and --run-id"
                )
            metadata = _collect_github_metadata(repository, run_id, timeout_seconds)
            temp = tempfile.TemporaryDirectory(prefix="devops-toolkit-ci-logs-")
            root = Path(temp.name)
            zip_path = root / "logs.zip"
            extracted = root / "extracted"
            extracted.mkdir()
            _download_github_logs(repository, run_id, zip_path, timeout_seconds)
            _extract_zip(zip_path, extracted, max_total_bytes=max_total_bytes)
            source = extracted
            target = f"github:{repository}:run:{run_id}"
        else:
            source = logs_dir
            target = str(logs_dir.resolve())
        logs = _collect_log_files(
            source,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
        findings, signatures, timeline = analyze_logs(logs)
        findings.extend(_job_findings(metadata))
        partial = not bool(logs)
        if partial:
            findings.append(
                Finding(
                    id="CI-NO-LOGS-COLLECTED",
                    tool=TOOL_NAME,
                    category="collection",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="No CI log files were collected",
                    recommendation="Verify the log source, run permissions, and configured size limits.",
                    evidence=Evidence(summary="log_file_count=0"),
                )
            )
        completed = utc_now()
        report = Report(
            metadata=ReportMetadata(
                tool=TOOL_NAME,
                tool_version=__version__,
                started_at=started,
                completed_at=completed,
                target=target,
                partial=partial,
                capabilities=[
                    "github-actions-log-download",
                    "offline-log-analysis",
                    "secret-redaction",
                    "failure-signature-grouping",
                    "sanitized-bundle",
                ],
            ),
            findings=findings,
            status=status_for_findings(findings, threshold, partial=partial),
            extensions={
                "log_files": sorted(logs),
                "signature_counts": signatures,
                "timeline": timeline,
                "run": metadata.get("run", {}),
            },
        )
        return report, logs, metadata
    finally:
        if temp is not None:
            temp.cleanup()
