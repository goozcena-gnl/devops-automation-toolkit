"""Deterministic secret scanning for working trees and bounded Git history."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

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
from devops_toolkit.core.redaction import fingerprint_sensitive
from devops_toolkit.core.subprocess import run_command
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "secret-sentinel"
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
}
PLACEHOLDER_WORDS = {
    "changeme",
    "example",
    "placeholder",
    "replace-me",
    "replace_me",
    "secret",
    "token",
    "your-key-here",
    "your_key_here",
}


@dataclass(frozen=True)
class SecretDetector:
    identifier: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    value_group: str | int = 0
    min_entropy: float = 0.0


DETECTORS: tuple[SecretDetector, ...] = (
    SecretDetector(
        "SECRET-PRIVATE-KEY",
        "Private key material detected",
        re.compile(
            r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
            r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
            re.DOTALL,
        ),
        Severity.CRITICAL,
    ),
    SecretDetector(
        "SECRET-GITHUB-TOKEN",
        "GitHub token detected",
        re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{20,}\b"),
        Severity.CRITICAL,
    ),
    SecretDetector(
        "SECRET-AWS-ACCESS-KEY",
        "AWS access-key identifier detected",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        Severity.HIGH,
    ),
    SecretDetector(
        "SECRET-AZURE-STORAGE-CONNECTION",
        "Azure Storage connection string detected",
        re.compile(
            r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;"
            r"AccountKey=(?P<value>[^;\s]{20,})"
        ),
        Severity.CRITICAL,
        value_group="value",
    ),
    SecretDetector(
        "SECRET-JWT",
        "JSON Web Token detected",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.HIGH,
        min_entropy=3.0,
    ),
    SecretDetector(
        "SECRET-GENERIC-ASSIGNMENT",
        "Potential hardcoded credential detected",
        re.compile(
            r"(?i)\b(?:password|passwd|token|api[_-]?key|client[_-]?secret|access[_-]?key)"
            r"\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9_./+=:@-]{12,})"
        ),
        Severity.HIGH,
        value_group="value",
        min_entropy=2.7,
    ),
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [value.count(character) / len(value) for character in set(value)]
    return -sum(probability * math.log2(probability) for probability in probabilities)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _is_placeholder(value: str) -> bool:
    normalized = value.strip("\"'").lower()
    return (
        normalized in PLACEHOLDER_WORDS
        or normalized.startswith("${")
        or normalized.startswith("{{")
    )


def scan_text(text: str, location: str, *, source: str = "working-tree") -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            value = match.group(detector.value_group)
            if _is_placeholder(value):
                continue
            if detector.min_entropy and shannon_entropy(value) < detector.min_entropy:
                continue
            line = _line_number(text, match.start())
            fingerprint = fingerprint_sensitive(
                f"{detector.identifier}\x1f{value}\x1f{location}\x1f{line}",
                namespace="secret-finding",
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            findings.append(
                Finding(
                    id=detector.identifier,
                    tool=TOOL_NAME,
                    category="secrets",
                    severity=detector.severity,
                    confidence=Confidence.HIGH
                    if detector.identifier != "SECRET-GENERIC-ASSIGNMENT"
                    else Confidence.MEDIUM,
                    title=detector.title,
                    description=(
                        "Sensitive material appears to be stored in source-controlled or local text."
                    ),
                    recommendation=(
                        "Revoke or rotate the credential, remove it from the source and history, "
                        "and replace it with workload identity or a managed secret store."
                    ),
                    fingerprint=fingerprint,
                    resource=ResourceRef(type="File", name=location),
                    evidence=Evidence(
                        summary=f"Detector {detector.identifier} matched in {source}",
                        location=location,
                        line=line,
                    ),
                )
            )
    return findings


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _read_text(path: Path, max_file_bytes: int) -> str | None:
    try:
        if path.is_symlink():
            return None
        if path.stat().st_size > max_file_bytes:
            return None
        data = path.read_bytes()
    except (OSError, PermissionError):
        return None
    if _looks_binary(data):
        return None
    return data.decode("utf-8", errors="replace")


def _walk_files(root: Path, excluded_dirs: set[str]) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(part in excluded_dirs for part in relative_parts):
            continue
        yield path


def _git_files(root: Path, *, include_ignored: bool, timeout_seconds: int) -> list[Path] | None:
    if not (root / ".git").exists():
        return None
    result = run_command(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        timeout_seconds=timeout_seconds,
    )
    if not result.succeeded:
        return None
    relative_paths = {item for item in result.stdout.split("\x00") if item}
    if include_ignored:
        ignored = run_command(
            ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
            cwd=root,
            timeout_seconds=timeout_seconds,
        )
        if not ignored.succeeded:
            return None
        relative_paths.update(item for item in ignored.stdout.split("\x00") if item)
    return [root / item for item in sorted(relative_paths)]


def _load_baseline(path: Path | None) -> set[str]:
    if path is None:
        return set()
    raw = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {
            line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#")
        }
    if isinstance(parsed, list):
        return {str(item) for item in parsed}
    if isinstance(parsed, dict) and isinstance(parsed.get("fingerprints"), list):
        return {str(item) for item in parsed["fingerprints"]}
    return set()


def scan_working_tree(
    root: Path,
    *,
    include_ignored: bool = False,
    max_file_bytes: int = 1_000_000,
    timeout_seconds: int = 30,
    excluded_dirs: set[str] | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    exclusions = DEFAULT_EXCLUDED_DIRS | (excluded_dirs or set())
    files = _git_files(root, include_ignored=include_ignored, timeout_seconds=timeout_seconds)
    if files is None:
        files = list(_walk_files(root, exclusions))
    findings: list[Finding] = []
    scanned = 0
    skipped = 0
    for path in files:
        if any(part in exclusions for part in path.relative_to(root).parts):
            continue
        text = _read_text(path, max_file_bytes)
        if text is None:
            skipped += 1
            continue
        scanned += 1
        findings.extend(scan_text(text, path.relative_to(root).as_posix()))
    return findings, {"files_scanned": scanned, "files_skipped": skipped}


def scan_git_history(
    root: Path,
    *,
    max_commits: int = 50,
    timeout_seconds: int = 30,
    excluded_dirs: set[str] | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    if not (root / ".git").exists() or max_commits <= 0:
        return [], {"commits_scanned": 0}
    revisions = run_command(
        ["git", "rev-list", "--all", f"--max-count={max_commits}"],
        cwd=root,
        timeout_seconds=timeout_seconds,
    )
    if not revisions.succeeded:
        return [], {"commits_scanned": 0}
    findings: list[Finding] = []
    failed = 0
    truncated = 0
    commits = [item for item in revisions.stdout.splitlines() if item]
    exclusions = DEFAULT_EXCLUDED_DIRS | (excluded_dirs or set())
    normalized_exclusions = [value.replace("\\", "/").strip("/") for value in exclusions]
    excluded_pathspecs = [f":(exclude){value}" for value in sorted(normalized_exclusions) if value]
    for commit in commits:
        result = run_command(
            [
                "git",
                "show",
                "--format=",
                "--no-ext-diff",
                "--unified=0",
                commit,
                "--",
                ".",
                *excluded_pathspecs,
            ],
            cwd=root,
            timeout_seconds=timeout_seconds,
            max_output_chars=5_000_000,
            sanitize_output=False,
        )
        if not result.succeeded:
            failed += 1
            continue
        if result.truncated:
            truncated += 1
        commit_findings = scan_text(result.stdout, f"git:{commit[:12]}", source="git-history")
        findings.extend(commit_findings)
    return findings, {
        "commits_scanned": len(commits),
        "commits_failed": failed,
        "commits_truncated": truncated,
    }


def build_report(
    root: Path,
    *,
    threshold: Severity = Severity.HIGH,
    include_ignored: bool = False,
    history: bool = False,
    max_commits: int = 50,
    max_file_bytes: int = 1_000_000,
    timeout_seconds: int = 30,
    baseline: Path | None = None,
    excluded_dirs: set[str] | None = None,
) -> Report:
    started = utc_now()
    findings, metrics = scan_working_tree(
        root,
        include_ignored=include_ignored,
        max_file_bytes=max_file_bytes,
        timeout_seconds=timeout_seconds,
        excluded_dirs=excluded_dirs,
    )
    if history:
        historical, history_metrics = scan_git_history(
            root,
            max_commits=max_commits,
            timeout_seconds=timeout_seconds,
            excluded_dirs=excluded_dirs,
        )
        findings.extend(historical)
        metrics.update(history_metrics)
    baseline_fingerprints = _load_baseline(baseline)
    deduplicated: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint in baseline_fingerprints:
            finding.suppressed = True
            finding.suppression_reason = "Accepted by local secret baseline"
        deduplicated.setdefault(finding.fingerprint, finding)
    final_findings = sorted(
        deduplicated.values(),
        key=lambda item: (item.evidence.location or "", item.evidence.line or 0, item.id),
    )
    history_partial = bool(metrics.get("commits_failed", 0) or metrics.get("commits_truncated", 0))
    completed = utc_now()
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=str(root.resolve()),
            partial=history_partial,
            capabilities=["working-tree", "git-history", "redaction", "sarif", "baseline"],
        ),
        findings=final_findings,
        status=status_for_findings(final_findings, threshold, partial=history_partial),
        extensions={"metrics": metrics, "history_enabled": history},
    )
