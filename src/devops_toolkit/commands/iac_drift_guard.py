"""Read-only Terraform/OpenTofu refresh-only drift guard and state-safety checks."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from devops_toolkit.core.exceptions import (
    CommandExecutionError,
    ConfigurationError,
    DependencyUnavailableError,
    SafetyBlockedError,
)
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
from devops_toolkit.core.safety import SafetyPolicy, require_safe_target
from devops_toolkit.core.subprocess import executable_path, run_command
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "iac-drift-guard"


def load_plan(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read drift plan JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Drift plan JSON root must be an object")
    if "resource_drift" not in payload and "resource_changes" not in payload:
        raise ConfigurationError("Input does not look like `terraform show -json` output")
    return payload


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    summary: str,
    recommendation: str,
    *,
    address: str,
    resource_type: str = "TerraformResource",
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="iac-drift",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Terraform/OpenTofu refresh comparison detected drift or a state-safety concern.",
        recommendation=recommendation,
        resource=ResourceRef(type=resource_type, name=address, identifier=address),
        evidence=Evidence(summary=summary, location=address),
    )


def analyze_plan(payload: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    drift = payload.get("resource_drift", [])
    if not isinstance(drift, list):
        raise ConfigurationError("Plan field `resource_drift` must be a list")
    findings: list[Finding] = []
    metrics = {
        "drifted_resources": 0,
        "updates": 0,
        "deletions": 0,
        "replacements": 0,
        "configuration_changes": 0,
        "failed_checks": 0,
    }
    for raw in drift:
        if not isinstance(raw, dict):
            continue
        address = str(raw.get("address", "unknown"))
        resource_type = str(raw.get("type", "TerraformResource"))
        change = raw.get("change", {})
        actions_raw = change.get("actions", []) if isinstance(change, dict) else []
        actions = [str(value) for value in actions_raw] if isinstance(actions_raw, list) else []
        action_set = set(actions)
        if not action_set or action_set <= {"no-op", "read"}:
            continue
        metrics["drifted_resources"] += 1
        if "delete" in action_set and "create" in action_set:
            metrics["replacements"] += 1
            severity = Severity.CRITICAL
            title = f"External drift implies resource replacement: {address}"
            identifier = "IAC-DRIFT-REPLACEMENT"
            recommendation = "Pause deployment, identify the external change and owner, validate data durability and dependencies, then decide whether to import, reconcile configuration, or deliberately replace the resource."
        elif "delete" in action_set:
            metrics["deletions"] += 1
            severity = Severity.CRITICAL
            title = f"Managed resource is missing remotely: {address}"
            identifier = "IAC-DRIFT-REMOTE-DELETION"
            recommendation = "Confirm whether the deletion was authorized, assess service impact and recovery requirements, and reconcile state only after ownership review."
        else:
            metrics["updates"] += 1
            severity = Severity.HIGH
            title = f"External modification detected: {address}"
            identifier = "IAC-DRIFT-EXTERNAL-UPDATE"
            recommendation = "Compare the before and after attributes, identify the change source, and restore the declared configuration or update IaC through review."
        findings.append(
            _finding(
                identifier,
                severity,
                title,
                f"actions={actions}; action_reason={raw.get('action_reason', 'not-reported')}",
                recommendation,
                address=address,
                resource_type=resource_type,
            )
        )

    changes = payload.get("resource_changes", [])
    if isinstance(changes, list):
        for raw in changes:
            if not isinstance(raw, dict):
                continue
            change = raw.get("change", {})
            actions_raw = change.get("actions", []) if isinstance(change, dict) else []
            actions = [str(value) for value in actions_raw] if isinstance(actions_raw, list) else []
            if set(actions) <= {"no-op", "read"}:
                continue
            metrics["configuration_changes"] += 1
    if metrics["configuration_changes"]:
        findings.append(
            _finding(
                "IAC-DRIFT-CONFIGURATION-CHANGES-PRESENT",
                Severity.MEDIUM,
                "Plan also contains configuration-driven changes",
                f"resource_change_count={metrics['configuration_changes']}",
                "Keep drift detection separate from deployment approval. Review configuration-driven changes with the Terraform Plan Risk Analyzer before applying anything.",
                address="plan",
                resource_type="TerraformPlan",
                confidence=Confidence.MEDIUM,
            )
        )

    checks = payload.get("checks", [])
    if isinstance(checks, list):
        for check in checks:
            if not isinstance(check, dict):
                continue
            status = str(check.get("status", "unknown")).lower()
            if status in {"fail", "error", "unknown"}:
                metrics["failed_checks"] += 1
        if metrics["failed_checks"]:
            findings.append(
                _finding(
                    "IAC-DRIFT-CHECKS-FAILED",
                    Severity.HIGH,
                    "Terraform checks are not passing",
                    f"failed_or_unknown_checks={metrics['failed_checks']}",
                    "Review failed preconditions, postconditions, and check blocks before using the drift result for remediation decisions.",
                    address="checks",
                    resource_type="TerraformChecks",
                )
            )
    return findings, metrics


def _state_safety_findings(root: Path, stale_lock_minutes: int) -> list[Finding]:
    findings: list[Finding] = []
    lock_path = root / ".terraform.tfstate.lock.info"
    if lock_path.exists():
        age_minutes = int((datetime.now(UTC).timestamp() - lock_path.stat().st_mtime) // 60)
        severity = Severity.HIGH if age_minutes >= stale_lock_minutes else Severity.MEDIUM
        findings.append(
            _finding(
                "IAC-STATE-LOCK-PRESENT",
                severity,
                "Terraform state lock file is present",
                f"path={lock_path}; age_minutes={age_minutes}; stale_review_threshold={stale_lock_minutes}",
                "Confirm whether another operation is running. Never force-unlock automatically; investigate the lock owner and backend before manual recovery.",
                address=str(lock_path),
                resource_type="TerraformStateLock",
                confidence=Confidence.MEDIUM,
            )
        )
    for candidate in (root / "terraform.tfstate", root / "terraform.tfstate.backup"):
        if not candidate.exists():
            continue
        try:
            mode = candidate.stat().st_mode & 0o777
        except OSError:
            continue
        if os.name != "nt" and mode & 0o077:
            findings.append(
                _finding(
                    "IAC-LOCAL-STATE-PERMISSIONS",
                    Severity.HIGH,
                    "Local Terraform state is readable by other users",
                    f"path={candidate}; mode={oct(mode)}",
                    "Move state to a secured remote backend and restrict local file permissions. State can contain credentials and sensitive resource attributes.",
                    address=str(candidate),
                    resource_type="TerraformState",
                )
            )
    return findings


def _workspace(binary: str, root: Path, timeout_seconds: int) -> str:
    result = run_command(
        [binary, "workspace", "show"],
        cwd=root,
        timeout_seconds=timeout_seconds,
        max_output_chars=10_000,
    )
    if not result.succeeded:
        detail = result.stderr or result.stdout or "unknown workspace failure"
        raise CommandExecutionError(f"Unable to determine Terraform workspace: {detail[:500]}")
    return result.stdout.strip() or "default"


def collect_plan(
    root: Path,
    *,
    binary: str,
    timeout_seconds: int,
    lock_timeout_seconds: int,
    var_files: list[Path],
) -> tuple[dict[str, Any], int, str]:
    if executable_path(binary) is None:
        raise DependencyUnavailableError(f"Required executable is unavailable: {binary}")
    if not root.is_dir():
        raise ConfigurationError(f"IaC root is not a directory: {root}")
    if not any(root.glob("*.tf")) and not any(root.glob("*.tofu")):
        raise ConfigurationError("No Terraform/OpenTofu configuration files were found")
    workspace = _workspace(binary, root, min(timeout_seconds, 30))
    with tempfile.TemporaryDirectory(prefix="devops-toolkit-drift-") as temp_dir:
        temp_root = Path(temp_dir)
        os.chmod(temp_root, 0o700)
        plan_path = temp_root / "refresh-only.plan"
        command = [
            binary,
            "plan",
            "-refresh-only",
            "-detailed-exitcode",
            "-input=false",
            "-no-color",
            f"-lock-timeout={lock_timeout_seconds}s",
            f"-out={plan_path}",
        ]
        for var_file in var_files:
            command.append(f"-var-file={var_file.resolve()}")
        result = run_command(
            command,
            cwd=root,
            timeout_seconds=timeout_seconds,
            max_output_chars=1_000_000,
        )
        if result.returncode not in {0, 2} or result.timed_out:
            detail = result.stderr or result.stdout or "unknown plan failure"
            raise CommandExecutionError(f"Refresh-only plan failed: {detail[:1000]}")
        show = run_command(
            [binary, "show", "-json", str(plan_path)],
            cwd=root,
            timeout_seconds=timeout_seconds,
            max_output_chars=20_000_000,
        )
        if not show.succeeded:
            detail = show.stderr or show.stdout or "unknown show failure"
            raise CommandExecutionError(f"Unable to render refresh-only plan JSON: {detail[:1000]}")
        try:
            payload = json.loads(show.stdout)
        except json.JSONDecodeError as exc:
            raise CommandExecutionError("Terraform/OpenTofu returned invalid plan JSON") from exc
        if not isinstance(payload, dict):
            raise CommandExecutionError("Terraform/OpenTofu plan JSON root is not an object")
        return payload, result.returncode, workspace


def build_report(
    root: Path,
    *,
    plan_json: Path | None = None,
    binary: str = "terraform",
    expected_workspace: str | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 300,
    lock_timeout_seconds: int = 15,
    stale_lock_minutes: int = 60,
    var_files: list[Path] | None = None,
    safety_policy: SafetyPolicy | None = None,
    production_acknowledged: bool = False,
) -> Report:
    started = utc_now()
    root = root.resolve()
    workspace = expected_workspace or "offline-plan"
    plan_exit_code: int | None = None
    if plan_json is None:
        payload, plan_exit_code, workspace = collect_plan(
            root,
            binary=binary,
            timeout_seconds=timeout_seconds,
            lock_timeout_seconds=lock_timeout_seconds,
            var_files=var_files or [],
        )
        if expected_workspace is not None and workspace != expected_workspace:
            raise SafetyBlockedError(
                f"Current workspace `{workspace}` does not match expected workspace `{expected_workspace}`"
            )
        if safety_policy is not None:
            require_safe_target(
                f"{root.name}/{workspace}",
                safety_policy,
                production_acknowledged=production_acknowledged,
            )
    else:
        payload = load_plan(plan_json)
        if safety_policy is not None and expected_workspace is not None:
            require_safe_target(
                expected_workspace,
                safety_policy,
                production_acknowledged=production_acknowledged,
            )
    findings, metrics = analyze_plan(payload)
    findings.extend(_state_safety_findings(root, stale_lock_minutes))
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=utc_now(),
            target=f"{root}:{workspace}",
            partial=False,
            capabilities=[
                "read-only",
                "refresh-only-plan" if plan_json is None else "offline-plan-json",
                "detailed-exitcode",
                "state-lock-review",
                "temporary-plan-cleanup",
                "no-apply",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold),
        extensions={
            "metrics": metrics,
            "binary": binary,
            "workspace": workspace,
            "plan_exit_code": plan_exit_code,
            "terraform_version": payload.get("terraform_version"),
            "format_version": payload.get("format_version"),
            "plan_files_persisted": False,
            "apply_executed": False,
        },
    )
