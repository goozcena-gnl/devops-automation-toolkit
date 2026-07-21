"""Terraform and OpenTofu JSON plan risk analyzer."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from devops_toolkit.core.exceptions import ConfigurationError
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
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "plan-risk"
STATEFUL_TYPE = re.compile(
    r"(?:database|db_instance|sql_|postgres|mysql|redis|cosmos|dynamodb|storage|disk|volume|bucket|vault|key_vault)",
    re.IGNORECASE,
)
PUBLIC_KEYS = {
    "publicly_accessible",
    "public_access_enabled",
    "public_network_access_enabled",
    "assign_public_ip",
    "associate_public_ip_address",
    "enable_public_ip",
}
ENCRYPTION_KEYS = {
    "encrypted",
    "encryption_enabled",
    "enable_encryption",
    "storage_encrypted",
}
RETENTION_KEYS = {
    "backup_retention_period",
    "retention_days",
    "soft_delete_retention_days",
    "delete_retention_policy_days",
}


def _resource(address: str, resource_type: str) -> ResourceRef:
    return ResourceRef(type=resource_type, name=address, identifier=address)


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    recommendation: str,
    address: str,
    resource_type: str,
    summary: str,
    *,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="terraform-plan",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Terraform plan JSON analysis identified a potentially risky infrastructure change.",
        recommendation=recommendation,
        resource=_resource(address, resource_type),
        evidence=Evidence(summary=summary, location=address),
    )


def _walk(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path, child
            yield from _walk(child, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}[{index}]"
            yield path, child
            yield from _walk(child, path)


def _wildcard_iam(value: Any) -> list[str]:
    matches: list[str] = []
    for path, child in _walk(value):
        leaf = path.rsplit(".", 1)[-1].lower()
        if leaf in {"action", "actions", "resource", "resources"}:
            values = child if isinstance(child, list) else [child]
            if any(
                item == "*" or (isinstance(item, str) and item.endswith(":*")) for item in values
            ):
                matches.append(path)
        if leaf in {"policy", "policy_document"} and isinstance(child, str) and '"*"' in child:
            matches.append(path)
    return matches


def _public_exposure(value: Any) -> list[str]:
    matches: list[str] = []
    for path, child in _walk(value):
        leaf = path.rsplit(".", 1)[-1].lower()
        if leaf in PUBLIC_KEYS and child is True:
            matches.append(path)
        if (
            isinstance(child, str)
            and child in {"0.0.0.0/0", "::/0", "*"}
            and any(marker in leaf for marker in ("cidr", "source", "address_prefix", "ip_range"))
        ):
            matches.append(path)
        if (
            isinstance(child, list)
            and any(isinstance(item, str) and item in {"0.0.0.0/0", "::/0", "*"} for item in child)
            and any(marker in leaf for marker in ("cidr", "source", "address_prefix", "ip_range"))
        ):
            matches.append(path)
    return matches


def _compare_controls(before: Any, after: Any) -> tuple[list[str], list[str]]:
    disabled_encryption: list[str] = []
    reduced_retention: list[str] = []
    before_map = dict(_walk(before)) if isinstance(before, dict | list) else {}
    after_map = dict(_walk(after)) if isinstance(after, dict | list) else {}
    for path, after_value in after_map.items():
        leaf = path.rsplit(".", 1)[-1].lower()
        before_value = before_map.get(path)
        if leaf in ENCRYPTION_KEYS and before_value is True and after_value is False:
            disabled_encryption.append(path)
        if (
            leaf in RETENTION_KEYS
            and isinstance(before_value, int | float)
            and isinstance(after_value, int | float)
            and after_value < before_value
        ):
            reduced_retention.append(f"{path}: {before_value} -> {after_value}")
    return disabled_encryption, reduced_retention


def analyze_plan(
    payload: dict[str, Any], *, replacement_threshold: int = 10
) -> tuple[list[Finding], dict[str, int]]:
    changes = payload.get("resource_changes", [])
    if not isinstance(changes, list):
        raise ConfigurationError("Terraform plan JSON field `resource_changes` must be a list")
    findings: list[Finding] = []
    metrics = {"create": 0, "update": 0, "delete": 0, "replace": 0, "no-op": 0, "read": 0}
    for raw_change in changes:
        if not isinstance(raw_change, dict):
            continue
        address = str(raw_change.get("address", "unknown"))
        resource_type = str(raw_change.get("type", "TerraformResource"))
        change = raw_change.get("change", {})
        if not isinstance(change, dict):
            continue
        actions_raw = change.get("actions", [])
        actions = [str(item) for item in actions_raw] if isinstance(actions_raw, list) else []
        action_set = set(actions)
        for action in action_set:
            if action in metrics:
                metrics[action] += 1
        replacing = "create" in action_set and "delete" in action_set
        if replacing:
            metrics["replace"] += 1
            severity = Severity.CRITICAL if STATEFUL_TYPE.search(resource_type) else Severity.HIGH
            findings.append(
                _finding(
                    "TFPLAN-RESOURCE-REPLACEMENT",
                    severity,
                    f"Resource `{address}` will be replaced",
                    "Review replacement triggers, data durability, downtime, dependencies, and rollback before approval.",
                    address,
                    resource_type,
                    f"actions={actions}",
                )
            )
        elif "delete" in action_set:
            severity = Severity.CRITICAL if STATEFUL_TYPE.search(resource_type) else Severity.HIGH
            findings.append(
                _finding(
                    "TFPLAN-RESOURCE-DELETION",
                    severity,
                    f"Resource `{address}` will be deleted",
                    "Confirm ownership, backups, dependencies, retention requirements, and explicit change approval.",
                    address,
                    resource_type,
                    f"actions={actions}",
                )
            )
        after = change.get("after")
        before = change.get("before")
        public_paths = _public_exposure(after)
        if public_paths:
            findings.append(
                _finding(
                    "TFPLAN-PUBLIC-EXPOSURE",
                    Severity.CRITICAL,
                    f"Resource `{address}` introduces public network exposure",
                    "Restrict source ranges, disable public access, use private endpoints, or document a reviewed exception.",
                    address,
                    resource_type,
                    f"public_paths={public_paths[:8]}",
                )
            )
        iam_paths = _wildcard_iam(after)
        if iam_paths:
            findings.append(
                _finding(
                    "TFPLAN-IAM-WILDCARD",
                    Severity.CRITICAL,
                    f"Resource `{address}` contains wildcard IAM permissions",
                    "Replace wildcard actions and resources with the smallest explicit permission set.",
                    address,
                    resource_type,
                    f"wildcard_paths={iam_paths[:8]}",
                )
            )
        encryption, retention = _compare_controls(before, after)
        if encryption:
            findings.append(
                _finding(
                    "TFPLAN-ENCRYPTION-DISABLED",
                    Severity.CRITICAL,
                    f"Resource `{address}` disables encryption",
                    "Keep encryption enabled and verify key ownership, rotation, and service compatibility.",
                    address,
                    resource_type,
                    f"changed_paths={encryption}",
                )
            )
        if retention:
            findings.append(
                _finding(
                    "TFPLAN-RETENTION-REDUCED",
                    Severity.HIGH,
                    f"Resource `{address}` reduces backup or retention settings",
                    "Confirm recovery objectives and compliance requirements before reducing retention.",
                    address,
                    resource_type,
                    f"changes={retention}",
                )
            )
    if metrics["replace"] >= replacement_threshold:
        findings.append(
            Finding(
                id="TFPLAN-REPLACEMENT-SPIKE",
                tool=TOOL_NAME,
                category="terraform-plan",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="Plan contains an unusually large replacement set",
                description="A high replacement count can indicate provider, state, addressing, or module migration problems.",
                recommendation="Pause deployment and review provider upgrades, moved blocks, state addresses, and module refactors.",
                resource=ResourceRef(type="TerraformPlan", name="plan"),
                evidence=Evidence(
                    summary=f"replacement_count={metrics['replace']}; threshold={replacement_threshold}"
                ),
            )
        )
    output_changes = payload.get("output_changes", {})
    if isinstance(output_changes, dict):
        for name, raw in output_changes.items():
            if not isinstance(raw, dict) or not raw.get("after_sensitive"):
                continue
            actions = raw.get("actions", [])
            if isinstance(actions, list) and any(
                action in {"create", "update"} for action in actions
            ):
                findings.append(
                    Finding(
                        id="TFPLAN-SENSITIVE-OUTPUT-CHANGE",
                        tool=TOOL_NAME,
                        category="terraform-plan",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"Sensitive output `{name}` changes",
                        recommendation="Verify downstream consumers and ensure the output is not exposed in CI logs or artifacts.",
                        resource=ResourceRef(type="TerraformOutput", name=str(name)),
                        evidence=Evidence(summary=f"actions={actions}"),
                    )
                )
    return findings, metrics


def load_plan(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read Terraform plan JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Terraform plan JSON root must be an object")
    if "resource_changes" not in payload:
        raise ConfigurationError(
            "Input does not look like `terraform show -json` output: missing resource_changes"
        )
    return payload


def build_report(
    plan_path: Path,
    *,
    threshold: Severity = Severity.HIGH,
    replacement_threshold: int = 10,
) -> Report:
    started = utc_now()
    payload = load_plan(plan_path)
    findings, metrics = analyze_plan(payload, replacement_threshold=replacement_threshold)
    completed = utc_now()
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=str(plan_path.resolve()),
            capabilities=[
                "resource-actions",
                "replacement-risk",
                "public-exposure",
                "iam-wildcards",
                "encryption-and-retention",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold),
        extensions={
            "metrics": metrics,
            "terraform_version": payload.get("terraform_version"),
            "format_version": payload.get("format_version"),
        },
    )
