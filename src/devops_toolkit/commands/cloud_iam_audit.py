"""Read-only Azure and AWS IAM exposure audit with deterministic snapshot support."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from devops_toolkit.core.exceptions import (
    CommandExecutionError,
    ConfigurationError,
    DependencyUnavailableError,
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
from devops_toolkit.core.subprocess import executable_path, run_command
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "cloud-iam-audit"
PRIVILEGED_AZURE_ROLES: dict[str, Severity] = {
    "owner": Severity.CRITICAL,
    "user access administrator": Severity.CRITICAL,
    "role based access control administrator": Severity.CRITICAL,
    "contributor": Severity.HIGH,
}
AWS_ADMIN_POLICY_NAMES = {"AdministratorAccess", "IAMFullAccess", "PowerUserAccess"}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read IAM snapshot: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("IAM snapshot root must be an object")
    return payload


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    summary: str,
    recommendation: str,
    *,
    provider: str,
    resource_type: str,
    resource_name: str,
    confidence: Confidence = Confidence.HIGH,
    references: list[str] | None = None,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="cloud-iam",
        severity=severity,
        confidence=confidence,
        title=title,
        description="The effective cloud identity configuration contains a potentially excessive or stale permission path.",
        recommendation=recommendation,
        resource=ResourceRef(
            type=resource_type,
            name=resource_name,
            provider=provider,
            identifier=resource_name,
        ),
        evidence=Evidence(summary=summary),
        references=references or [],
    )


def _is_broad_azure_scope(scope: str, subscription_id: str | None) -> bool:
    normalized = scope.rstrip("/").lower()
    if normalized in {"", "/"}:
        return True
    if "/providers/microsoft.management/managementgroups/" in normalized:
        return True
    return bool(subscription_id and normalized == f"/subscriptions/{subscription_id.lower()}")


def analyze_azure(payload: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    subscription = payload.get("subscription", {})
    subscription_id = (
        str(subscription.get("id"))
        if isinstance(subscription, dict) and subscription.get("id")
        else None
    )
    findings: list[Finding] = []
    metrics = {
        "role_assignments": 0,
        "broad_privileged_assignments": 0,
        "unknown_principals": 0,
        "custom_roles_with_wildcards": 0,
        "expired_credentials": 0,
        "expiring_credentials": 0,
    }

    assignments = payload.get("role_assignments", payload.get("roleAssignments", []))
    if isinstance(assignments, list):
        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            metrics["role_assignments"] += 1
            role = str(
                assignment.get("roleDefinitionName")
                or assignment.get("role_name")
                or assignment.get("roleName")
                or "unknown"
            )
            scope = str(assignment.get("scope", "unknown"))
            principal = str(
                assignment.get("principalName")
                or assignment.get("principalDisplayName")
                or assignment.get("principalId")
                or "unknown-principal"
            )
            principal_type = str(assignment.get("principalType", "unknown"))
            role_severity = PRIVILEGED_AZURE_ROLES.get(role.lower())
            if role_severity and _is_broad_azure_scope(scope, subscription_id):
                metrics["broad_privileged_assignments"] += 1
                findings.append(
                    _finding(
                        "AZURE-IAM-BROAD-PRIVILEGED-ROLE",
                        role_severity,
                        f"Broad {role} assignment",
                        f"principal={principal}; principal_type={principal_type}; scope={scope}",
                        "Replace the assignment with the narrowest built-in or custom role at the smallest practical scope, then validate dependent workflows.",
                        provider="azure",
                        resource_type="RoleAssignment",
                        resource_name=principal,
                        references=[
                            "https://learn.microsoft.com/azure/role-based-access-control/best-practices"
                        ],
                    )
                )
            if principal_type.lower() in {"unknown", "deleted", ""} or principal.lower().startswith(
                "unknown"
            ):
                metrics["unknown_principals"] += 1
                findings.append(
                    _finding(
                        "AZURE-IAM-UNKNOWN-PRINCIPAL",
                        Severity.HIGH,
                        "Role assignment references an unknown principal",
                        f"role={role}; scope={scope}; principal_identifier={principal}",
                        "Confirm whether the identity was deleted and remove the orphaned assignment after dependency review.",
                        provider="azure",
                        resource_type="RoleAssignment",
                        resource_name=principal,
                        confidence=Confidence.MEDIUM,
                    )
                )

    definitions = payload.get("role_definitions", payload.get("roleDefinitions", []))
    if isinstance(definitions, list):
        for definition in definitions:
            if not isinstance(definition, dict):
                continue
            role_name = str(
                definition.get("roleName") or definition.get("role_name") or "custom-role"
            )
            role_type = str(definition.get("roleType") or definition.get("role_type") or "")
            if role_type.lower() not in {"customrole", "custom"}:
                continue
            permissions = definition.get("permissions", [])
            wildcard_actions: list[str] = []
            if isinstance(permissions, list):
                for permission in permissions:
                    if not isinstance(permission, dict):
                        continue
                    for key in ("actions", "dataActions"):
                        values = permission.get(key, [])
                        if isinstance(values, list):
                            wildcard_actions.extend(
                                str(value)
                                for value in values
                                if isinstance(value, str) and "*" in value
                            )
            if wildcard_actions:
                metrics["custom_roles_with_wildcards"] += 1
                severity = Severity.CRITICAL if "*" in wildcard_actions else Severity.HIGH
                findings.append(
                    _finding(
                        "AZURE-IAM-CUSTOM-ROLE-WILDCARD",
                        severity,
                        f"Custom role contains wildcard permissions: {role_name}",
                        f"wildcard_actions={','.join(sorted(set(wildcard_actions))[:10])}",
                        "Replace wildcard actions with an explicit operation allowlist and add NotActions only as a secondary safeguard.",
                        provider="azure",
                        resource_type="RoleDefinition",
                        resource_name=role_name,
                    )
                )

    now = datetime.now(UTC)
    principals = payload.get("service_principals", payload.get("servicePrincipals", []))
    if isinstance(principals, list):
        for principal in principals:
            if not isinstance(principal, dict):
                continue
            name = str(
                principal.get("displayName")
                or principal.get("name")
                or principal.get("id")
                or "service-principal"
            )
            credentials = principal.get("credentials", [])
            if not isinstance(credentials, list):
                continue
            for credential in credentials:
                if not isinstance(credential, dict):
                    continue
                raw_end = credential.get("endDateTime") or credential.get("end_date")
                if not isinstance(raw_end, str):
                    continue
                try:
                    end = datetime.fromisoformat(raw_end.replace("Z", "+00:00"))
                except ValueError:
                    continue
                days = int((end - now).total_seconds() // 86400)
                if days < 0:
                    metrics["expired_credentials"] += 1
                    severity = Severity.HIGH
                    identifier = "AZURE-IAM-EXPIRED-CREDENTIAL"
                    title = f"Expired service-principal credential: {name}"
                elif days <= 30:
                    metrics["expiring_credentials"] += 1
                    severity = Severity.MEDIUM
                    identifier = "AZURE-IAM-EXPIRING-CREDENTIAL"
                    title = f"Service-principal credential expires soon: {name}"
                else:
                    continue
                findings.append(
                    _finding(
                        identifier,
                        severity,
                        title,
                        f"credential_type={credential.get('type', 'unknown')}; days_remaining={days}; secret_value=not_collected",
                        "Rotate or remove the credential, prefer workload identity or managed identity, and verify that no dependent workload uses the old credential.",
                        provider="azure",
                        resource_type="ServicePrincipal",
                        resource_name=name,
                    )
                )
    return findings, metrics


def _decode_policy(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    text = unquote(value)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _policy_risks(document: dict[str, Any]) -> tuple[bool, bool, list[str]]:
    admin = False
    broad_resource = False
    actions: list[str] = []
    statements = document.get("Statement", [])
    for statement in _as_list(statements):
        if not isinstance(statement, dict) or str(statement.get("Effect", "Allow")) != "Allow":
            continue
        statement_actions = [str(item) for item in _as_list(statement.get("Action", []))]
        resources = [str(item) for item in _as_list(statement.get("Resource", []))]
        actions.extend(statement_actions)
        if "*" in statement_actions:
            admin = True
        if "*" in resources:
            broad_resource = True
    return admin, broad_resource, actions


def _iter_inline_policies(detail: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    results: list[tuple[str, dict[str, Any]]] = []
    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):
        values = detail.get(key, [])
        if not isinstance(values, list):
            continue
        for policy in values:
            if not isinstance(policy, dict):
                continue
            name = str(policy.get("PolicyName", "inline-policy"))
            results.append((name, _decode_policy(policy.get("PolicyDocument"))))
    return results


def _trust_risks(
    document: dict[str, Any], account_id: str | None
) -> list[tuple[str, Severity, str]]:
    risks: list[tuple[str, Severity, str]] = []
    for statement in _as_list(document.get("Statement", [])):
        if not isinstance(statement, dict) or str(statement.get("Effect", "Allow")) != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            risks.append(("AWS-IAM-PUBLIC-TRUST", Severity.CRITICAL, "principal=*"))
            continue
        aws_values: list[str] = []
        if isinstance(principal, dict):
            aws_values = [str(item) for item in _as_list(principal.get("AWS", []))]
        for value in aws_values:
            if value.endswith(":root") and (
                account_id is None or f"::{account_id}:root" not in value
            ):
                risks.append(
                    ("AWS-IAM-EXTERNAL-ACCOUNT-TRUST", Severity.HIGH, f"principal={value}")
                )
    return risks


def analyze_aws(payload: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    identity = payload.get("identity", {})
    account_id = (
        str(identity.get("Account"))
        if isinstance(identity, dict) and identity.get("Account")
        else None
    )
    auth = payload.get("authorization_details", payload.get("authorizationDetails", payload))
    if not isinstance(auth, dict):
        raise ConfigurationError("AWS authorization_details must be an object")
    findings: list[Finding] = []
    metrics = {
        "identities": 0,
        "admin_policies": 0,
        "broad_resource_policies": 0,
        "public_trusts": 0,
        "external_account_trusts": 0,
        "users_without_mfa": 0,
        "stale_access_keys": 0,
    }

    for list_key, kind, name_key in (
        ("UserDetailList", "IAMUser", "UserName"),
        ("RoleDetailList", "IAMRole", "RoleName"),
        ("GroupDetailList", "IAMGroup", "GroupName"),
    ):
        details = auth.get(list_key, [])
        if not isinstance(details, list):
            continue
        for detail in details:
            if not isinstance(detail, dict):
                continue
            metrics["identities"] += 1
            name = str(detail.get(name_key, "unknown"))
            attached = detail.get("AttachedManagedPolicies", [])
            if isinstance(attached, list):
                for policy in attached:
                    if not isinstance(policy, dict):
                        continue
                    policy_name = str(policy.get("PolicyName", ""))
                    if policy_name in AWS_ADMIN_POLICY_NAMES:
                        metrics["admin_policies"] += 1
                        findings.append(
                            _finding(
                                "AWS-IAM-ADMIN-MANAGED-POLICY",
                                Severity.CRITICAL
                                if policy_name == "AdministratorAccess"
                                else Severity.HIGH,
                                f"Administrative managed policy attached to {name}",
                                f"policy={policy_name}; identity_type={kind}",
                                "Replace the policy with task-specific permissions and validate access using IAM policy simulation or Access Analyzer.",
                                provider="aws",
                                resource_type=kind,
                                resource_name=name,
                                references=[
                                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                                ],
                            )
                        )
            for policy_name, document in _iter_inline_policies(detail):
                admin, broad_resource, actions = _policy_risks(document)
                if admin:
                    metrics["admin_policies"] += 1
                    findings.append(
                        _finding(
                            "AWS-IAM-INLINE-ADMIN-POLICY",
                            Severity.CRITICAL,
                            f"Inline policy grants all actions: {name}",
                            f"policy={policy_name}; action=*; resource_scope={'*' if broad_resource else 'restricted'}",
                            "Replace `Action: *` with an explicit action allowlist and constrain resources and conditions.",
                            provider="aws",
                            resource_type=kind,
                            resource_name=name,
                        )
                    )
                elif broad_resource and actions:
                    metrics["broad_resource_policies"] += 1
                    findings.append(
                        _finding(
                            "AWS-IAM-BROAD-RESOURCE-POLICY",
                            Severity.HIGH,
                            f"Policy grants actions against all resources: {name}",
                            f"policy={policy_name}; actions={','.join(actions[:10])}; resource=*",
                            "Scope the resource ARN set and add conditions where the service supports resource-level authorization.",
                            provider="aws",
                            resource_type=kind,
                            resource_name=name,
                            confidence=Confidence.MEDIUM,
                        )
                    )
            if kind == "IAMRole":
                trust = _decode_policy(detail.get("AssumeRolePolicyDocument"))
                for identifier, severity, summary in _trust_risks(trust, account_id):
                    if identifier == "AWS-IAM-PUBLIC-TRUST":
                        metrics["public_trusts"] += 1
                    else:
                        metrics["external_account_trusts"] += 1
                    findings.append(
                        _finding(
                            identifier,
                            severity,
                            f"Risky role trust policy: {name}",
                            summary,
                            "Restrict trusted principals, require an external ID for third parties where applicable, and add organization or source conditions.",
                            provider="aws",
                            resource_type=kind,
                            resource_name=name,
                        )
                    )

    credential_report = payload.get("credential_report", payload.get("credentialReport", []))
    rows = (
        credential_report.get("rows", [])
        if isinstance(credential_report, dict)
        else credential_report
    )
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            user = str(row.get("user", row.get("User", "unknown")))
            password_enabled = str(row.get("password_enabled", "false")).lower() == "true"
            mfa_active = str(row.get("mfa_active", "false")).lower() == "true"
            if password_enabled and not mfa_active:
                metrics["users_without_mfa"] += 1
                severity = Severity.CRITICAL if user == "<root_account>" else Severity.HIGH
                findings.append(
                    _finding(
                        "AWS-IAM-CONSOLE-WITHOUT-MFA",
                        severity,
                        f"Console-enabled identity lacks MFA: {user}",
                        "password_enabled=true; mfa_active=false",
                        "Enable phishing-resistant MFA and remove console access when it is not operationally required.",
                        provider="aws",
                        resource_type="IAMUser",
                        resource_name=user,
                    )
                )
            for slot in (1, 2):
                active = str(row.get(f"access_key_{slot}_active", "false")).lower() == "true"
                age_value = row.get(f"access_key_{slot}_age_days")
                try:
                    age_days = int(age_value) if age_value is not None else 0
                except (TypeError, ValueError):
                    age_days = 0
                if active and age_days > 90:
                    metrics["stale_access_keys"] += 1
                    findings.append(
                        _finding(
                            "AWS-IAM-STALE-ACCESS-KEY",
                            Severity.HIGH,
                            f"Long-lived access key is still active: {user}",
                            f"key_slot={slot}; age_days={age_days}; access_key_id=not_collected",
                            "Rotate and disable the access key, then migrate the workload to an IAM role, OIDC federation, or another short-lived credential mechanism.",
                            provider="aws",
                            resource_type="IAMUser",
                            resource_name=user,
                        )
                    )
    return findings, metrics


def _parse_json_result(command: list[str], timeout_seconds: int) -> dict[str, Any] | list[Any]:
    result = run_command(command, timeout_seconds=timeout_seconds, max_output_chars=5_000_000)
    if not result.succeeded:
        detail = result.stderr or result.stdout or "unknown CLI failure"
        raise CommandExecutionError(f"Command failed: {' '.join(command[:3])}: {detail[:500]}")
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CommandExecutionError(
            f"Command returned invalid JSON: {' '.join(command[:3])}"
        ) from exc
    if not isinstance(parsed, (dict, list)):
        raise CommandExecutionError(
            f"Command returned an unsupported JSON root: {' '.join(command[:3])}"
        )
    return parsed


def collect_azure(subscription: str | None, timeout_seconds: int) -> dict[str, Any]:
    if executable_path("az") is None:
        raise DependencyUnavailableError("Required executable is unavailable: az")
    subscription_args = ["--subscription", subscription] if subscription else []
    account = _parse_json_result(
        ["az", "account", "show", *subscription_args, "--output", "json"], timeout_seconds
    )
    assignments = _parse_json_result(
        [
            "az",
            "role",
            "assignment",
            "list",
            "--all",
            "--include-inherited",
            *subscription_args,
            "--output",
            "json",
        ],
        timeout_seconds,
    )
    definitions = _parse_json_result(
        ["az", "role", "definition", "list", *subscription_args, "--output", "json"],
        timeout_seconds,
    )
    return {
        "provider": "azure",
        "subscription": account if isinstance(account, dict) else {},
        "role_assignments": assignments if isinstance(assignments, list) else [],
        "role_definitions": definitions if isinstance(definitions, list) else [],
        "service_principals": [],
        "collection_notes": [
            "Service-principal credential expiry was not collected because it requires additional Microsoft Graph permissions."
        ],
    }


def collect_aws(profile: str | None, timeout_seconds: int) -> dict[str, Any]:
    if executable_path("aws") is None:
        raise DependencyUnavailableError("Required executable is unavailable: aws")
    profile_args = ["--profile", profile] if profile else []
    identity = _parse_json_result(
        ["aws", "sts", "get-caller-identity", *profile_args, "--output", "json", "--no-cli-pager"],
        timeout_seconds,
    )
    details = _parse_json_result(
        [
            "aws",
            "iam",
            "get-account-authorization-details",
            *profile_args,
            "--output",
            "json",
            "--no-cli-pager",
        ],
        timeout_seconds,
    )
    return {
        "provider": "aws",
        "identity": identity if isinstance(identity, dict) else {},
        "authorization_details": details if isinstance(details, dict) else {},
        "credential_report": [],
        "collection_notes": [
            "Credential report analysis is available through offline snapshots; live collection avoids generating or retrieving account credential reports."
        ],
    }


def build_report(
    *,
    provider: str,
    snapshot_path: Path | None = None,
    subscription: str | None = None,
    profile: str | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 60,
) -> Report:
    started = utc_now()
    normalized_provider = provider.lower()
    if normalized_provider not in {"azure", "aws"}:
        raise ConfigurationError("provider must be `azure` or `aws`")
    payload = (
        _load_json(snapshot_path)
        if snapshot_path
        else (
            collect_azure(subscription, timeout_seconds)
            if normalized_provider == "azure"
            else collect_aws(profile, timeout_seconds)
        )
    )
    payload_provider = str(payload.get("provider", normalized_provider)).lower()
    if payload_provider != normalized_provider:
        raise ConfigurationError(
            f"Snapshot provider `{payload_provider}` does not match requested provider `{normalized_provider}`"
        )
    findings, metrics = (
        analyze_azure(payload) if normalized_provider == "azure" else analyze_aws(payload)
    )
    notes = payload.get("collection_notes", [])
    partial = bool(notes) and snapshot_path is None
    target = (
        str(payload.get("subscription", {}).get("id", subscription or "current-subscription"))
        if normalized_provider == "azure" and isinstance(payload.get("subscription"), dict)
        else str(payload.get("identity", {}).get("Account", profile or "current-account"))
        if isinstance(payload.get("identity"), dict)
        else profile or "current-account"
    )
    report = Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=utc_now(),
            target=f"{normalized_provider}:{target}",
            partial=partial,
            capabilities=[
                "read-only",
                "offline-snapshot" if snapshot_path else "live-cli-collection",
                f"provider:{normalized_provider}",
                "secret-values-not-collected",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={
            "provider": normalized_provider,
            "metrics": metrics,
            "collection_notes": notes if isinstance(notes, list) else [],
        },
    )
    return report
