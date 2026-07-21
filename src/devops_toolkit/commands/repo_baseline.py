"""Read-only GitHub repository governance baseline auditor."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from devops_toolkit.core.exceptions import ConfigurationError, DependencyUnavailableError
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
from devops_toolkit.version import __version__

TOOL_NAME = "repo-baseline"
CONTENT_PATHS = {
    "security_policy": ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"],
    "codeowners": ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"],
    "dependabot": [".github/dependabot.yml", ".github/dependabot.yaml"],
}


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    recommendation: str,
    repository: str,
    summary: str,
    *,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="github-governance",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Repository configuration does not meet the selected security and governance baseline.",
        recommendation=recommendation,
        resource=ResourceRef(type="GitHubRepository", name=repository, provider="github"),
        evidence=Evidence(summary=summary, location=repository),
    )


def _gh_json(arguments: list[str], *, timeout_seconds: int) -> tuple[Any, str | None, int]:
    result = run_command(
        ["gh", "api", *arguments],
        timeout_seconds=timeout_seconds,
        max_output_chars=2_000_000,
        sanitize_output=False,
    )
    if result.timed_out:
        return None, "request timed out", result.returncode
    if result.returncode != 0:
        return None, Redactor().redact(result.stderr or result.stdout)[:500], result.returncode
    try:
        return json.loads(result.stdout), None, result.returncode
    except json.JSONDecodeError:
        return None, "GitHub CLI returned invalid JSON", result.returncode


def collect_repository(
    repository: str, *, timeout_seconds: int = 30
) -> tuple[dict[str, Any], dict[str, str], bool]:
    if executable_path("gh") is None:
        raise DependencyUnavailableError("Required executable is unavailable: gh")
    auth = run_command(["gh", "auth", "status"], timeout_seconds=timeout_seconds)
    if not auth.succeeded:
        raise ConfigurationError("GitHub CLI is not authenticated")
    snapshot: dict[str, Any] = {"repository": repository, "contents": {}}
    errors: dict[str, str] = {}
    metadata, error, _ = _gh_json([f"repos/{repository}"], timeout_seconds=timeout_seconds)
    if error or not isinstance(metadata, dict):
        raise ConfigurationError(f"Unable to read GitHub repository metadata: {error}")
    snapshot["metadata"] = metadata
    default_branch = str(metadata.get("default_branch", "main"))
    endpoints = {
        "branch_protection": f"repos/{repository}/branches/{default_branch}/protection",
        "rulesets": f"repos/{repository}/rulesets?includes_parents=true",
        "actions_permissions": f"repos/{repository}/actions/permissions/workflow",
    }
    for key, endpoint in endpoints.items():
        payload, endpoint_error, _returncode = _gh_json([endpoint], timeout_seconds=timeout_seconds)
        if endpoint_error:
            missing_protection = key == "branch_protection" and (
                "HTTP 404" in endpoint_error or "Not Found" in endpoint_error
            )
            if missing_protection:
                snapshot[key] = None
            else:
                errors[key] = endpoint_error
        else:
            snapshot[key] = payload
    contents: dict[str, bool] = {}
    for key, candidates in CONTENT_PATHS.items():
        found = False
        for candidate in candidates:
            payload, endpoint_error, _ = _gh_json(
                [f"repos/{repository}/contents/{candidate}"], timeout_seconds=timeout_seconds
            )
            if endpoint_error is None and isinstance(payload, dict):
                found = True
                break
        contents[key] = found
    snapshot["contents"] = contents
    return snapshot, errors, bool(errors)


def load_snapshot(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read repository snapshot: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Repository snapshot root must be an object")
    return payload


def analyze_snapshot(snapshot: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    repository = str(snapshot.get("repository", "unknown/unknown"))
    metadata = snapshot.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ConfigurationError("Repository snapshot metadata must be an object")
    findings: list[Finding] = []
    metrics: dict[str, Any] = {
        "default_branch": metadata.get("default_branch"),
        "visibility": metadata.get("visibility", "unknown"),
        "archived": bool(metadata.get("archived", False)),
    }
    if metadata.get("archived"):
        findings.append(
            _finding(
                "GITHUB-REPOSITORY-ARCHIVED",
                Severity.INFO,
                "Repository is archived",
                "Treat archived status as intentional and remove active CI credentials or integrations that are no longer needed.",
                repository,
                "archived=true",
            )
        )
    protection = snapshot.get("branch_protection")
    rulesets = snapshot.get("rulesets", [])
    enabled_rulesets = (
        [
            item
            for item in rulesets
            if isinstance(item, dict)
            and str(item.get("enforcement", "")).lower() in {"active", "enabled"}
        ]
        if isinstance(rulesets, list)
        else []
    )
    if not isinstance(protection, dict) and not enabled_rulesets:
        findings.append(
            _finding(
                "GITHUB-DEFAULT-BRANCH-UNPROTECTED",
                Severity.CRITICAL,
                "Default branch has no effective protection or active ruleset",
                "Enable branch protection or a ruleset requiring pull requests, reviews, status checks, and restricted destructive operations.",
                repository,
                f"default_branch={metadata.get('default_branch', 'unknown')}",
            )
        )
    if isinstance(protection, dict):
        reviews = protection.get("required_pull_request_reviews")
        if not isinstance(reviews, dict):
            findings.append(
                _finding(
                    "GITHUB-REVIEWS-NOT-REQUIRED",
                    Severity.HIGH,
                    "Pull-request reviews are not required",
                    "Require at least one approval and consider code-owner and last-push approval for sensitive repositories.",
                    repository,
                    "required_pull_request_reviews absent",
                )
            )
        else:
            if int(reviews.get("required_approving_review_count", 0) or 0) < 1:
                findings.append(
                    _finding(
                        "GITHUB-APPROVAL-COUNT-ZERO",
                        Severity.HIGH,
                        "Required approving review count is zero",
                        "Require at least one approving review before merge.",
                        repository,
                        "required_approving_review_count=0",
                    )
                )
            if reviews.get("require_code_owner_reviews") is not True:
                findings.append(
                    _finding(
                        "GITHUB-CODEOWNER-REVIEW-NOT-REQUIRED",
                        Severity.MEDIUM,
                        "Code-owner review is not required",
                        "Require code-owner review for protected paths or document why it is unnecessary.",
                        repository,
                        "require_code_owner_reviews=false",
                    )
                )
        checks = protection.get("required_status_checks")
        contexts = checks.get("contexts", []) if isinstance(checks, dict) else []
        checks_list = checks.get("checks", []) if isinstance(checks, dict) else []
        if not contexts and not checks_list:
            findings.append(
                _finding(
                    "GITHUB-STATUS-CHECKS-NOT-REQUIRED",
                    Severity.HIGH,
                    "No status checks are required before merge",
                    "Require trusted build, test, security, and policy checks on the default branch.",
                    repository,
                    "required_status_checks empty",
                )
            )
        for field, identifier, title, recommendation, severity in (
            (
                "allow_force_pushes",
                "GITHUB-FORCE-PUSH-ALLOWED",
                "Force pushes are allowed",
                "Disable force pushes on the default branch.",
                Severity.CRITICAL,
            ),
            (
                "allow_deletions",
                "GITHUB-BRANCH-DELETION-ALLOWED",
                "Default branch deletion is allowed",
                "Disable branch deletion for the default branch.",
                Severity.CRITICAL,
            ),
        ):
            value = protection.get(field)
            enabled = value.get("enabled") if isinstance(value, dict) else value
            if enabled is True:
                findings.append(
                    _finding(
                        identifier, severity, title, recommendation, repository, f"{field}=true"
                    )
                )
        conversation = protection.get("required_conversation_resolution")
        conversation_enabled = (
            conversation.get("enabled") if isinstance(conversation, dict) else conversation
        )
        if conversation_enabled is not True:
            findings.append(
                _finding(
                    "GITHUB-CONVERSATION-RESOLUTION-NOT-REQUIRED",
                    Severity.MEDIUM,
                    "Review conversations need not be resolved",
                    "Require conversation resolution before merge.",
                    repository,
                    "required_conversation_resolution=false",
                )
            )
    contents = snapshot.get("contents", {})
    if not isinstance(contents, dict):
        contents = {}
    for key, identifier, severity, title, recommendation in (
        (
            "security_policy",
            "GITHUB-SECURITY-POLICY-MISSING",
            Severity.MEDIUM,
            "SECURITY.md is missing",
            "Publish supported versions, reporting instructions, and coordinated disclosure expectations.",
        ),
        (
            "codeowners",
            "GITHUB-CODEOWNERS-MISSING",
            Severity.MEDIUM,
            "CODEOWNERS is missing",
            "Define accountable reviewers for sensitive and operationally critical paths.",
        ),
        (
            "dependabot",
            "GITHUB-DEPENDABOT-CONFIG-MISSING",
            Severity.MEDIUM,
            "Dependabot configuration is missing",
            "Configure scheduled dependency updates for supported ecosystems and GitHub Actions.",
        ),
    ):
        if contents.get(key) is not True:
            findings.append(
                _finding(identifier, severity, title, recommendation, repository, f"{key}=false")
            )
    actions = snapshot.get("actions_permissions")
    if isinstance(actions, dict):
        default_permission = str(actions.get("default_workflow_permissions", ""))
        if default_permission == "write":
            findings.append(
                _finding(
                    "GITHUB-ACTIONS-DEFAULT-WRITE",
                    Severity.HIGH,
                    "GitHub Actions receives write permission by default",
                    "Set the default workflow permission to read and grant write access only to specific jobs.",
                    repository,
                    "default_workflow_permissions=write",
                )
            )
        if actions.get("can_approve_pull_request_reviews") is True:
            findings.append(
                _finding(
                    "GITHUB-ACTIONS-CAN-APPROVE",
                    Severity.HIGH,
                    "GitHub Actions can approve pull requests",
                    "Disable workflow approval of pull requests unless a reviewed automation use case requires it.",
                    repository,
                    "can_approve_pull_request_reviews=true",
                )
            )
    security = metadata.get("security_and_analysis", {})
    if isinstance(security, dict):
        for key, identifier, severity, title, recommendation in (
            (
                "secret_scanning",
                "GITHUB-SECRET-SCANNING-DISABLED",
                Severity.HIGH,
                "Secret scanning is disabled",
                "Enable secret scanning where the repository plan supports it.",
            ),
            (
                "secret_scanning_push_protection",
                "GITHUB-PUSH-PROTECTION-DISABLED",
                Severity.HIGH,
                "Secret scanning push protection is disabled",
                "Enable push protection to block supported secrets before they enter Git history.",
            ),
            (
                "dependabot_security_updates",
                "GITHUB-DEPENDABOT-SECURITY-UPDATES-DISABLED",
                Severity.MEDIUM,
                "Dependabot security updates are disabled",
                "Enable automated security update pull requests where supported.",
            ),
        ):
            value = security.get(key)
            status = value.get("status") if isinstance(value, dict) else value
            if status == "disabled":
                findings.append(
                    _finding(
                        identifier, severity, title, recommendation, repository, f"{key}=disabled"
                    )
                )
    return findings, metrics


def build_report(
    repository: str | None = None,
    *,
    snapshot_path: Path | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 30,
) -> Report:
    started = utc_now()
    errors: dict[str, str] = {}
    if snapshot_path is not None:
        snapshot = load_snapshot(snapshot_path)
    else:
        if not repository:
            raise ConfigurationError("Provide a repository in OWNER/REPO form or --snapshot")
        snapshot, errors, _ = collect_repository(repository, timeout_seconds=timeout_seconds)
    findings, metrics = analyze_snapshot(snapshot)
    repo_name = str(snapshot.get("repository", repository or "unknown/unknown"))
    for area, error in errors.items():
        findings.append(
            _finding(
                "GITHUB-COLLECTION-INCOMPLETE",
                Severity.MEDIUM,
                f"Unable to collect GitHub baseline area `{area}`",
                "Verify token scopes, repository visibility, plan availability, and API connectivity.",
                repo_name,
                error,
                confidence=Confidence.HIGH,
            )
        )
    completed = utc_now()
    partial = bool(errors)
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=repo_name,
            partial=partial,
            capabilities=[
                "branch-protection",
                "rulesets",
                "repository-files",
                "actions-permissions",
                "security-features",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={
            "metrics": metrics,
            "collection_errors": errors,
            "offline_snapshot": snapshot_path is not None,
        },
    )
