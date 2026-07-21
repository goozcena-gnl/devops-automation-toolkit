"""Read-only Azure and AWS cloud waste inventory with evidence-based recommendations."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

TOOL_NAME = "cloud-waste"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read cloud waste snapshot: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Cloud waste snapshot root must be an object")
    return payload


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _age_days(resource: dict[str, Any], now: datetime) -> int | None:
    explicit = resource.get("age_days")
    if isinstance(explicit, int):
        return explicit
    for key in ("created_at", "timeCreated", "CreateTime", "StartTime", "creation_time"):
        created = _parse_time(resource.get(key))
        if created is not None:
            return max(0, int((now - created).total_seconds() // 86400))
    return None


def _resource_name(resource: dict[str, Any]) -> str:
    return str(
        resource.get("name")
        or resource.get("Name")
        or resource.get("id")
        or resource.get("resource_id")
        or "unknown"
    )


def _resource_id(resource: dict[str, Any]) -> str:
    return str(
        resource.get("id")
        or resource.get("resource_id")
        or resource.get("arn")
        or _resource_name(resource)
    )


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    summary: str,
    recommendation: str,
    *,
    provider: str,
    resource: dict[str, Any],
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    resource_type = str(resource.get("type") or resource.get("resource_type") or "CloudResource")
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="cloud-finops",
        severity=severity,
        confidence=confidence,
        title=title,
        description="The resource appears unused, orphaned, idle, or outside the configured governance baseline.",
        recommendation=recommendation,
        resource=ResourceRef(
            type=resource_type,
            name=_resource_name(resource),
            provider=provider,
            identifier=_resource_id(resource),
        ),
        evidence=Evidence(
            summary=summary,
            location=str(resource.get("region") or resource.get("location") or "unknown"),
        ),
    )


def analyze_resources(
    payload: dict[str, Any],
    *,
    snapshot_age_days: int = 30,
    idle_age_days: int = 14,
    idle_utilization_percent: float = 5.0,
    required_tags: set[str] | None = None,
) -> tuple[list[Finding], dict[str, int | float]]:
    provider = str(payload.get("provider", "unknown")).lower()
    resources = payload.get("resources", [])
    if not isinstance(resources, list):
        raise ConfigurationError("Cloud waste snapshot `resources` must be a list")
    findings: list[Finding] = []
    required = required_tags or set()
    now = datetime.now(UTC)
    metrics: dict[str, int | float] = {
        "resources_analyzed": 0,
        "unattached_storage": 0,
        "unassociated_public_ips": 0,
        "orphaned_interfaces": 0,
        "old_snapshots": 0,
        "empty_load_balancers": 0,
        "idle_compute": 0,
        "missing_required_tags": 0,
        "estimated_monthly_waste": 0.0,
    }

    for resource in resources:
        if not isinstance(resource, dict):
            continue
        metrics["resources_analyzed"] = int(metrics["resources_analyzed"]) + 1
        resource_type = str(resource.get("type") or resource.get("resource_type") or "").lower()
        age = _age_days(resource, now)
        estimated = resource.get("estimated_monthly_cost", 0)
        try:
            estimated_cost = max(0.0, float(estimated))
        except (TypeError, ValueError):
            estimated_cost = 0.0

        attached = resource.get("attached")
        if (
            resource_type
            in {
                "disk",
                "volume",
                "microsoft.compute/disks",
                "aws::ec2::volume",
            }
            and attached is False
        ):
            metrics["unattached_storage"] = int(metrics["unattached_storage"]) + 1
            metrics["estimated_monthly_waste"] = (
                float(metrics["estimated_monthly_waste"]) + estimated_cost
            )
            findings.append(
                _finding(
                    "CLOUD-WASTE-UNATTACHED-STORAGE",
                    Severity.HIGH if estimated_cost >= 100 else Severity.MEDIUM,
                    f"Unattached storage resource: {_resource_name(resource)}",
                    f"attached=false; age_days={age if age is not None else 'unknown'}; estimated_monthly_cost={estimated_cost:.2f}",
                    "Confirm backup and ownership requirements, snapshot if policy requires it, then remove through the normal change process. This tool does not delete resources.",
                    provider=provider,
                    resource=resource,
                )
            )

        associated = resource.get("associated")
        if (
            resource_type
            in {
                "publicipaddress",
                "public_ip",
                "elastic_ip",
                "microsoft.network/publicipaddresses",
                "aws::ec2::eip",
            }
            and associated is False
        ):
            metrics["unassociated_public_ips"] = int(metrics["unassociated_public_ips"]) + 1
            metrics["estimated_monthly_waste"] = (
                float(metrics["estimated_monthly_waste"]) + estimated_cost
            )
            findings.append(
                _finding(
                    "CLOUD-WASTE-UNASSOCIATED-PUBLIC-IP",
                    Severity.MEDIUM,
                    f"Unassociated public IP: {_resource_name(resource)}",
                    f"associated=false; age_days={age if age is not None else 'unknown'}; estimated_monthly_cost={estimated_cost:.2f}",
                    "Verify DNS, allowlists, and pending deployments before releasing the address through an approved change.",
                    provider=provider,
                    resource=resource,
                )
            )

        if (
            resource_type
            in {
                "networkinterface",
                "network_interface",
                "microsoft.network/networkinterfaces",
                "aws::ec2::networkinterface",
            }
            and attached is False
        ):
            metrics["orphaned_interfaces"] = int(metrics["orphaned_interfaces"]) + 1
            findings.append(
                _finding(
                    "CLOUD-WASTE-ORPHANED-NETWORK-INTERFACE",
                    Severity.LOW,
                    f"Unattached network interface: {_resource_name(resource)}",
                    f"attached=false; state={resource.get('state', 'unknown')}; age_days={age if age is not None else 'unknown'}",
                    "Confirm that the interface is not reserved for failover or a pending deployment, then remove it through the normal change process.",
                    provider=provider,
                    resource=resource,
                    confidence=Confidence.MEDIUM,
                )
            )

        if (
            resource_type
            in {
                "snapshot",
                "microsoft.compute/snapshots",
                "aws::ec2::snapshot",
            }
            and age is not None
            and age >= snapshot_age_days
        ):
            metrics["old_snapshots"] = int(metrics["old_snapshots"]) + 1
            metrics["estimated_monthly_waste"] = (
                float(metrics["estimated_monthly_waste"]) + estimated_cost
            )
            findings.append(
                _finding(
                    "CLOUD-WASTE-OLD-SNAPSHOT",
                    Severity.LOW,
                    f"Snapshot exceeds retention review threshold: {_resource_name(resource)}",
                    f"age_days={age}; review_threshold_days={snapshot_age_days}; estimated_monthly_cost={estimated_cost:.2f}",
                    "Validate retention, legal hold, recovery objectives, and source-resource status before deleting or tiering the snapshot.",
                    provider=provider,
                    resource=resource,
                    confidence=Confidence.MEDIUM,
                )
            )

        target_count = resource.get("target_count", resource.get("backend_count"))
        if (
            resource_type
            in {
                "loadbalancer",
                "load_balancer",
                "microsoft.network/loadbalancers",
                "aws::elasticloadbalancingv2::loadbalancer",
            }
            and isinstance(target_count, int)
            and target_count == 0
        ):
            metrics["empty_load_balancers"] = int(metrics["empty_load_balancers"]) + 1
            metrics["estimated_monthly_waste"] = (
                float(metrics["estimated_monthly_waste"]) + estimated_cost
            )
            findings.append(
                _finding(
                    "CLOUD-WASTE-EMPTY-LOAD-BALANCER",
                    Severity.MEDIUM,
                    f"Load balancer has no registered targets: {_resource_name(resource)}",
                    f"target_count=0; age_days={age if age is not None else 'unknown'}; estimated_monthly_cost={estimated_cost:.2f}",
                    "Confirm whether this is a standby endpoint or deployment placeholder, then remove it through an approved change if unused.",
                    provider=provider,
                    resource=resource,
                    confidence=Confidence.MEDIUM,
                )
            )

        utilization = resource.get("utilization_percent")
        try:
            utilization_value = float(utilization) if utilization is not None else None
        except (TypeError, ValueError):
            utilization_value = None
        if (
            resource_type
            in {
                "virtualmachine",
                "instance",
                "compute",
                "microsoft.compute/virtualmachines",
                "aws::ec2::instance",
            }
            and utilization_value is not None
            and age is not None
            and age >= idle_age_days
            and utilization_value <= idle_utilization_percent
        ):
            metrics["idle_compute"] = int(metrics["idle_compute"]) + 1
            metrics["estimated_monthly_waste"] = (
                float(metrics["estimated_monthly_waste"]) + estimated_cost
            )
            findings.append(
                _finding(
                    "CLOUD-WASTE-IDLE-COMPUTE",
                    Severity.HIGH if estimated_cost >= 100 else Severity.MEDIUM,
                    f"Compute resource appears idle: {_resource_name(resource)}",
                    f"utilization_percent={utilization_value:.2f}; threshold_percent={idle_utilization_percent:.2f}; observation_age_days={age}; estimated_monthly_cost={estimated_cost:.2f}",
                    "Validate application schedules and percentile metrics over a representative window before stopping, resizing, or removing the resource.",
                    provider=provider,
                    resource=resource,
                    confidence=Confidence.MEDIUM,
                )
            )

        tags = resource.get("tags", {})
        tag_keys = {str(key) for key in tags} if isinstance(tags, dict) else set()
        missing = sorted(required - tag_keys)
        if missing:
            metrics["missing_required_tags"] = int(metrics["missing_required_tags"]) + 1
            findings.append(
                _finding(
                    "CLOUD-WASTE-MISSING-REQUIRED-TAGS",
                    Severity.LOW,
                    f"Resource is missing governance tags: {_resource_name(resource)}",
                    f"missing_tags={','.join(missing)}",
                    "Add the required ownership, environment, cost-center, and lifecycle tags through the authoritative IaC source.",
                    provider=provider,
                    resource=resource,
                )
            )
    metrics["estimated_monthly_waste"] = round(float(metrics["estimated_monthly_waste"]), 2)
    return findings, metrics


def _json_command(command: list[str], timeout_seconds: int) -> dict[str, Any] | list[Any]:
    result = run_command(command, timeout_seconds=timeout_seconds, max_output_chars=10_000_000)
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


def _azure_tags(item: dict[str, Any]) -> dict[str, str]:
    tags = item.get("tags", {})
    return {str(key): str(value) for key, value in tags.items()} if isinstance(tags, dict) else {}


def collect_azure(subscription: str | None, timeout_seconds: int) -> dict[str, Any]:
    if executable_path("az") is None:
        raise DependencyUnavailableError("Required executable is unavailable: az")
    sub_args = ["--subscription", subscription] if subscription else []
    account = _json_command(["az", "account", "show", *sub_args, "-o", "json"], timeout_seconds)
    commands = {
        "disks": ["az", "disk", "list", *sub_args, "-o", "json"],
        "public_ips": ["az", "network", "public-ip", "list", *sub_args, "-o", "json"],
        "snapshots": ["az", "snapshot", "list", *sub_args, "-o", "json"],
        "nics": ["az", "network", "nic", "list", *sub_args, "-o", "json"],
        "load_balancers": ["az", "network", "lb", "list", *sub_args, "-o", "json"],
    }
    collected = {key: _json_command(command, timeout_seconds) for key, command in commands.items()}
    resources: list[dict[str, Any]] = []
    for item in collected["disks"] if isinstance(collected["disks"], list) else []:
        if isinstance(item, dict):
            resources.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "type": "microsoft.compute/disks",
                    "region": item.get("location"),
                    "tags": _azure_tags(item),
                    "timeCreated": item.get("timeCreated"),
                    "attached": bool(item.get("managedBy")),
                    "state": item.get("diskState"),
                }
            )
    for item in collected["public_ips"] if isinstance(collected["public_ips"], list) else []:
        if isinstance(item, dict):
            resources.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "type": "microsoft.network/publicipaddresses",
                    "region": item.get("location"),
                    "tags": _azure_tags(item),
                    "associated": bool(item.get("ipConfiguration")),
                    "state": item.get("provisioningState"),
                }
            )
    for item in collected["snapshots"] if isinstance(collected["snapshots"], list) else []:
        if isinstance(item, dict):
            resources.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "type": "microsoft.compute/snapshots",
                    "region": item.get("location"),
                    "tags": _azure_tags(item),
                    "timeCreated": item.get("timeCreated"),
                    "state": item.get("provisioningState"),
                }
            )
    for item in collected["nics"] if isinstance(collected["nics"], list) else []:
        if isinstance(item, dict):
            resources.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "type": "microsoft.network/networkinterfaces",
                    "region": item.get("location"),
                    "tags": _azure_tags(item),
                    "attached": bool(item.get("virtualMachine")),
                    "state": item.get("provisioningState"),
                }
            )
    for item in (
        collected["load_balancers"] if isinstance(collected["load_balancers"], list) else []
    ):
        if isinstance(item, dict):
            pools = item.get("backendAddressPools", [])
            backend_count = 0
            if isinstance(pools, list):
                for pool in pools:
                    if isinstance(pool, dict):
                        backend_count += (
                            len(pool.get("backendAddresses", []))
                            if isinstance(pool.get("backendAddresses"), list)
                            else 0
                        )
            resources.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "type": "microsoft.network/loadbalancers",
                    "region": item.get("location"),
                    "tags": _azure_tags(item),
                    "backend_count": backend_count,
                    "state": item.get("provisioningState"),
                }
            )
    return {
        "provider": "azure",
        "scope": account.get("id", subscription or "current-subscription")
        if isinstance(account, dict)
        else subscription or "current-subscription",
        "resources": resources,
        "collection_notes": [
            "Utilization metrics and exact prices are not collected by the live inventory; idle-compute and cost totals require enriched snapshots."
        ],
    }


def _aws_tags(items: object) -> dict[str, str]:
    result: dict[str, str] = {}
    if isinstance(items, list):
        for tag in items:
            if isinstance(tag, dict) and tag.get("Key") is not None:
                result[str(tag["Key"])] = str(tag.get("Value", ""))
    return result


def collect_aws(profile: str | None, region: str | None, timeout_seconds: int) -> dict[str, Any]:
    if executable_path("aws") is None:
        raise DependencyUnavailableError("Required executable is unavailable: aws")
    common = (
        (["--profile", profile] if profile else [])
        + (["--region", region] if region else [])
        + ["--output", "json", "--no-cli-pager"]
    )
    identity = _json_command(["aws", "sts", "get-caller-identity", *common], timeout_seconds)
    volumes = _json_command(["aws", "ec2", "describe-volumes", *common], timeout_seconds)
    addresses = _json_command(["aws", "ec2", "describe-addresses", *common], timeout_seconds)
    snapshots = _json_command(
        ["aws", "ec2", "describe-snapshots", "--owner-ids", "self", *common], timeout_seconds
    )
    interfaces = _json_command(
        ["aws", "ec2", "describe-network-interfaces", *common], timeout_seconds
    )
    resources: list[dict[str, Any]] = []
    if isinstance(volumes, dict):
        for item in volumes.get("Volumes", []):
            if isinstance(item, dict):
                resources.append(
                    {
                        "id": item.get("VolumeId"),
                        "name": item.get("VolumeId"),
                        "type": "aws::ec2::volume",
                        "region": item.get("AvailabilityZone"),
                        "tags": _aws_tags(item.get("Tags")),
                        "CreateTime": item.get("CreateTime"),
                        "attached": bool(item.get("Attachments")),
                        "state": item.get("State"),
                    }
                )
    if isinstance(addresses, dict):
        for item in addresses.get("Addresses", []):
            if isinstance(item, dict):
                identifier = item.get("AllocationId") or item.get("PublicIp")
                resources.append(
                    {
                        "id": identifier,
                        "name": identifier,
                        "type": "aws::ec2::eip",
                        "region": region,
                        "tags": _aws_tags(item.get("Tags")),
                        "associated": bool(item.get("AssociationId")),
                    }
                )
    if isinstance(snapshots, dict):
        for item in snapshots.get("Snapshots", []):
            if isinstance(item, dict):
                resources.append(
                    {
                        "id": item.get("SnapshotId"),
                        "name": item.get("SnapshotId"),
                        "type": "aws::ec2::snapshot",
                        "region": region,
                        "tags": _aws_tags(item.get("Tags")),
                        "StartTime": item.get("StartTime"),
                        "state": item.get("State"),
                    }
                )
    if isinstance(interfaces, dict):
        for item in interfaces.get("NetworkInterfaces", []):
            if isinstance(item, dict):
                resources.append(
                    {
                        "id": item.get("NetworkInterfaceId"),
                        "name": item.get("NetworkInterfaceId"),
                        "type": "aws::ec2::networkinterface",
                        "region": item.get("AvailabilityZone") or region,
                        "tags": _aws_tags(item.get("TagSet")),
                        "attached": bool(item.get("Attachment")),
                        "state": item.get("Status"),
                    }
                )
    return {
        "provider": "aws",
        "scope": identity.get("Account", profile or "current-account")
        if isinstance(identity, dict)
        else profile or "current-account",
        "resources": resources,
        "collection_notes": [
            "Utilization metrics, load-balancer target health, and exact prices are not collected by the live inventory; use an enriched snapshot for those findings."
        ],
    }


def build_report(
    *,
    provider: str,
    snapshot_path: Path | None = None,
    subscription: str | None = None,
    profile: str | None = None,
    region: str | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 90,
    snapshot_age_days: int = 30,
    idle_age_days: int = 14,
    idle_utilization_percent: float = 5.0,
    required_tags: set[str] | None = None,
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
            else collect_aws(profile, region, timeout_seconds)
        )
    )
    actual_provider = str(payload.get("provider", normalized_provider)).lower()
    if actual_provider != normalized_provider:
        raise ConfigurationError(
            f"Snapshot provider `{actual_provider}` does not match `{normalized_provider}`"
        )
    findings, metrics = analyze_resources(
        payload,
        snapshot_age_days=snapshot_age_days,
        idle_age_days=idle_age_days,
        idle_utilization_percent=idle_utilization_percent,
        required_tags=required_tags,
    )
    notes = payload.get("collection_notes", [])
    partial = bool(notes) and snapshot_path is None
    target = str(payload.get("scope", subscription or profile or "current-scope"))
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=utc_now(),
            target=f"{normalized_provider}:{target}",
            partial=partial,
            capabilities=[
                "read-only",
                "report-only",
                "offline-snapshot" if snapshot_path else "live-cli-collection",
                f"provider:{normalized_provider}",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={
            "provider": normalized_provider,
            "metrics": metrics,
            "required_tags": sorted(required_tags or set()),
            "collection_notes": notes if isinstance(notes, list) else [],
            "destructive_actions_available": False,
        },
    )
