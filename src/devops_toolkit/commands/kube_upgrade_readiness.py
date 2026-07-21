"""Read-only Kubernetes upgrade-readiness assessment with target-version policy."""

from __future__ import annotations

import json
import re
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
from devops_toolkit.core.safety import SafetyPolicy, require_safe_target
from devops_toolkit.core.subprocess import executable_path, run_command
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "kube-upgrade-readiness"
VERSION_RE = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")
# High-value removals from the Kubernetes deprecated API migration guide.
REMOVED_APIS: dict[str, tuple[int, int, str]] = {
    "extensions/v1beta1:Ingress": (1, 22, "networking.k8s.io/v1"),
    "networking.k8s.io/v1beta1:Ingress": (1, 22, "networking.k8s.io/v1"),
    "apiextensions.k8s.io/v1beta1:CustomResourceDefinition": (1, 22, "apiextensions.k8s.io/v1"),
    "admissionregistration.k8s.io/v1beta1:MutatingWebhookConfiguration": (
        1,
        22,
        "admissionregistration.k8s.io/v1",
    ),
    "admissionregistration.k8s.io/v1beta1:ValidatingWebhookConfiguration": (
        1,
        22,
        "admissionregistration.k8s.io/v1",
    ),
    "authentication.k8s.io/v1beta1:TokenReview": (1, 22, "authentication.k8s.io/v1"),
    "authorization.k8s.io/v1beta1:SubjectAccessReview": (1, 22, "authorization.k8s.io/v1"),
    "certificates.k8s.io/v1beta1:CertificateSigningRequest": (1, 22, "certificates.k8s.io/v1"),
    "coordination.k8s.io/v1beta1:Lease": (1, 22, "coordination.k8s.io/v1"),
    "policy/v1beta1:PodSecurityPolicy": (1, 25, "Pod Security Admission or another policy engine"),
    "policy/v1beta1:PodDisruptionBudget": (1, 25, "policy/v1"),
    "batch/v1beta1:CronJob": (1, 25, "batch/v1"),
    "autoscaling/v2beta1:HorizontalPodAutoscaler": (1, 25, "autoscaling/v2"),
    "autoscaling/v2beta2:HorizontalPodAutoscaler": (1, 26, "autoscaling/v2"),
    "flowcontrol.apiserver.k8s.io/v1beta1:FlowSchema": (
        1,
        26,
        "flowcontrol.apiserver.k8s.io/v1beta3 or v1",
    ),
    "flowcontrol.apiserver.k8s.io/v1beta1:PriorityLevelConfiguration": (
        1,
        26,
        "flowcontrol.apiserver.k8s.io/v1beta3 or v1",
    ),
    "storage.k8s.io/v1beta1:CSIStorageCapacity": (1, 27, "storage.k8s.io/v1"),
    "flowcontrol.apiserver.k8s.io/v1beta2:FlowSchema": (
        1,
        29,
        "flowcontrol.apiserver.k8s.io/v1beta3 or v1",
    ),
    "flowcontrol.apiserver.k8s.io/v1beta2:PriorityLevelConfiguration": (
        1,
        29,
        "flowcontrol.apiserver.k8s.io/v1beta3 or v1",
    ),
    "flowcontrol.apiserver.k8s.io/v1beta3:FlowSchema": (1, 32, "flowcontrol.apiserver.k8s.io/v1"),
    "flowcontrol.apiserver.k8s.io/v1beta3:PriorityLevelConfiguration": (
        1,
        32,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
}


def _version(value: object) -> tuple[int, int, int]:
    text = str(value or "")
    match = VERSION_RE.search(text)
    if not match:
        raise ConfigurationError(f"Unable to parse Kubernetes version: {text!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _version_text(value: tuple[int, int, int]) -> str:
    return f"{value[0]}.{value[1]}.{value[2]}"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read Kubernetes upgrade snapshot: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Kubernetes upgrade snapshot root must be an object")
    return payload


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    summary: str,
    recommendation: str,
    *,
    kind: str,
    name: str,
    namespace: str | None = None,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="kubernetes-upgrade",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Cluster evidence indicates a potential blocker or review item for the requested Kubernetes target version.",
        recommendation=recommendation,
        resource=ResourceRef(type=kind, name=name, namespace=namespace, provider="kubernetes"),
        evidence=Evidence(summary=summary, location=f"{namespace}/{name}" if namespace else name),
        references=[
            "https://kubernetes.io/docs/reference/using-api/deprecation-guide/",
            "https://kubernetes.io/releases/version-skew-policy/",
        ],
    )


def _metadata(item: dict[str, Any]) -> tuple[str, str | None]:
    metadata = item.get("metadata", {})
    if not isinstance(metadata, dict):
        return "unknown", None
    return str(metadata.get("name", "unknown")), str(metadata.get("namespace")) if metadata.get(
        "namespace"
    ) else None


def _items(payload: object) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        values = payload.get("items", [])
        return (
            [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []
        )
    return []


def analyze_snapshot(
    payload: dict[str, Any],
    *,
    target_version: str,
) -> tuple[list[Finding], dict[str, int | str]]:
    target = _version(target_version)
    version_payload = payload.get("version", payload)
    if not isinstance(version_payload, dict):
        raise ConfigurationError("Snapshot version data must be an object")
    server_raw = (
        version_payload.get("server")
        or version_payload.get("serverVersion")
        or payload.get("server_version")
    )
    client_raw = (
        version_payload.get("client")
        or version_payload.get("clientVersion")
        or payload.get("client_version")
    )
    if isinstance(server_raw, dict):
        server_raw = (
            server_raw.get("gitVersion")
            or f"{server_raw.get('major', '')}.{str(server_raw.get('minor', '')).rstrip('+')}"
        )
    if isinstance(client_raw, dict):
        client_raw = (
            client_raw.get("gitVersion")
            or f"{client_raw.get('major', '')}.{str(client_raw.get('minor', '')).rstrip('+')}"
        )
    server = _version(server_raw)
    client = _version(client_raw) if client_raw else server
    if target[:2] < server[:2]:
        raise ConfigurationError(
            f"Target version {target_version} is older than current server version {_version_text(server)}"
        )
    findings: list[Finding] = []
    metrics: dict[str, int | str] = {
        "current_server_version": _version_text(server),
        "client_version": _version_text(client),
        "target_version": _version_text(target),
        "unhealthy_nodes": 0,
        "node_skew_blockers": 0,
        "removed_api_usages": 0,
        "risky_pdbs": 0,
        "webhook_review_items": 0,
        "crd_storage_issues": 0,
        "api_services_unavailable": 0,
        "addons_inventoried": 0,
    }

    if target[1] - server[1] > 1:
        findings.append(
            _finding(
                "KUBE-UPGRADE-MINOR-SKIP",
                Severity.CRITICAL,
                "Upgrade target skips one or more Kubernetes minor versions",
                f"current={_version_text(server)}; target={_version_text(target)}; minor_gap={target[1] - server[1]}",
                "Plan sequential control-plane upgrades one minor version at a time and re-run readiness checks at every step.",
                kind="Cluster",
                name="control-plane",
            )
        )
    if abs(client[1] - server[1]) > 1:
        findings.append(
            _finding(
                "KUBE-UPGRADE-KUBECTL-SKEW",
                Severity.HIGH,
                "kubectl is outside supported minor-version skew",
                f"kubectl={_version_text(client)}; server={_version_text(server)}",
                "Use a kubectl version within one minor version of every API server it can contact.",
                kind="Client",
                name="kubectl",
            )
        )

    nodes_payload = payload.get("nodes", {})
    for node in _items(nodes_payload):
        name, _ = _metadata(node)
        status = node.get("status", {})
        if not isinstance(status, dict):
            status = {}
        conditions = status.get("conditions", [])
        ready = False
        if isinstance(conditions, list):
            ready = any(
                isinstance(condition, dict)
                and condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in conditions
            )
        if not ready:
            metrics["unhealthy_nodes"] = int(metrics["unhealthy_nodes"]) + 1
            findings.append(
                _finding(
                    "KUBE-UPGRADE-NODE-NOT-READY",
                    Severity.CRITICAL,
                    f"Node is not Ready: {name}",
                    "Ready condition is not True",
                    "Restore node health and workload redundancy before beginning the control-plane or node upgrade.",
                    kind="Node",
                    name=name,
                )
            )
        node_info = status.get("nodeInfo", {})
        kubelet_raw = node_info.get("kubeletVersion") if isinstance(node_info, dict) else None
        if kubelet_raw:
            kubelet = _version(kubelet_raw)
            if kubelet[:2] > server[:2]:
                metrics["node_skew_blockers"] = int(metrics["node_skew_blockers"]) + 1
                findings.append(
                    _finding(
                        "KUBE-UPGRADE-KUBELET-NEWER-THAN-SERVER",
                        Severity.CRITICAL,
                        f"kubelet is newer than the API server: {name}",
                        f"kubelet={_version_text(kubelet)}; server={_version_text(server)}",
                        "Restore supported component ordering before upgrading; kubelet must not be newer than kube-apiserver.",
                        kind="Node",
                        name=name,
                    )
                )
            if target[1] - kubelet[1] > 3:
                metrics["node_skew_blockers"] = int(metrics["node_skew_blockers"]) + 1
                findings.append(
                    _finding(
                        "KUBE-UPGRADE-KUBELET-TARGET-SKEW",
                        Severity.HIGH,
                        f"Node kubelet will be too old for target control plane: {name}",
                        f"kubelet={_version_text(kubelet)}; target={_version_text(target)}; minor_gap={target[1] - kubelet[1]}",
                        "Upgrade kubelets in the supported sequence and drain nodes before minor-version kubelet upgrades.",
                        kind="Node",
                        name=name,
                    )
                )

    api_usages = payload.get("api_usages", payload.get("apiUsages", []))
    if isinstance(api_usages, list):
        for item in api_usages:
            if not isinstance(item, dict):
                continue
            api_version = str(item.get("apiVersion", ""))
            kind = str(item.get("kind", "unknown"))
            name = str(item.get("name", "unknown"))
            namespace = str(item.get("namespace")) if item.get("namespace") else None
            key = f"{api_version}:{kind}"
            removal = REMOVED_APIS.get(key)
            if removal and target[:2] >= removal[:2]:
                metrics["removed_api_usages"] = int(metrics["removed_api_usages"]) + 1
                findings.append(
                    _finding(
                        "KUBE-UPGRADE-REMOVED-API-USAGE",
                        Severity.CRITICAL,
                        f"Resource uses an API removed before target: {kind}/{name}",
                        f"api_version={api_version}; removed_in={removal[0]}.{removal[1]}; target={_version_text(target)}",
                        f"Migrate the manifest or client to {removal[2]}, deploy it through the authoritative source, and verify stored objects before upgrading.",
                        kind=kind,
                        name=name,
                        namespace=namespace,
                    )
                )
            elif "beta" in api_version:
                findings.append(
                    _finding(
                        "KUBE-UPGRADE-BETA-API-REVIEW",
                        Severity.LOW,
                        f"Resource still uses a beta API: {kind}/{name}",
                        f"api_version={api_version}; target={_version_text(target)}",
                        "Check the target-version API reference and migrate to a stable version when available.",
                        kind=kind,
                        name=name,
                        namespace=namespace,
                        confidence=Confidence.MEDIUM,
                    )
                )

    served_versions = payload.get("api_versions", payload.get("apiVersions", []))
    if isinstance(served_versions, list):
        served = {str(value) for value in served_versions}
        for key, removal in REMOVED_APIS.items():
            api_version, kind = key.split(":", 1)
            if api_version in served and target[:2] >= removal[:2]:
                findings.append(
                    _finding(
                        "KUBE-UPGRADE-REMOVED-API-SERVED",
                        Severity.MEDIUM,
                        f"Current server still advertises an API unavailable at target: {api_version}",
                        f"api_version={api_version}; representative_kind={kind}; removed_in={removal[0]}.{removal[1]}",
                        "Search manifests, audit logs, clients, and controllers for requests to this API before the upgrade.",
                        kind="APIGroupVersion",
                        name=api_version,
                        confidence=Confidence.MEDIUM,
                    )
                )

    for pdb in _items(payload.get("poddisruptionbudgets", payload.get("pdbs", {}))):
        name, namespace = _metadata(pdb)
        status = pdb.get("status", {})
        spec = pdb.get("spec", {})
        if not isinstance(status, dict):
            status = {}
        if not isinstance(spec, dict):
            spec = {}
        disruptions = status.get("disruptionsAllowed")
        current_healthy = status.get("currentHealthy")
        desired_healthy = status.get("desiredHealthy")
        rigid = spec.get("minAvailable") == "100%" or spec.get("maxUnavailable") in {0, "0", "0%"}
        if disruptions == 0 and (
            rigid
            or (
                isinstance(current_healthy, int)
                and isinstance(desired_healthy, int)
                and current_healthy <= desired_healthy
            )
        ):
            metrics["risky_pdbs"] = int(metrics["risky_pdbs"]) + 1
            findings.append(
                _finding(
                    "KUBE-UPGRADE-PDB-BLOCKS-DISRUPTION",
                    Severity.HIGH,
                    f"PodDisruptionBudget may block node drains: {namespace}/{name}",
                    f"disruptions_allowed=0; current_healthy={current_healthy}; desired_healthy={desired_healthy}; min_available={spec.get('minAvailable')}; max_unavailable={spec.get('maxUnavailable')}",
                    "Restore replica health or adjust the disruption policy through review before draining nodes.",
                    kind="PodDisruptionBudget",
                    name=name,
                    namespace=namespace,
                )
            )

    for collection_name in ("mutating_webhooks", "validating_webhooks", "webhooks"):
        for configuration in _items(payload.get(collection_name, {})):
            config_name, _ = _metadata(configuration)
            webhooks = configuration.get("webhooks", [])
            if not isinstance(webhooks, list):
                continue
            for webhook in webhooks:
                if not isinstance(webhook, dict):
                    continue
                name = str(webhook.get("name", config_name))
                match_policy = str(webhook.get("matchPolicy", "Equivalent"))
                timeout = webhook.get("timeoutSeconds", 10)
                admission_versions = webhook.get("admissionReviewVersions", [])
                risky = (
                    match_policy != "Equivalent"
                    or not admission_versions
                    or (isinstance(timeout, int) and timeout > 10)
                )
                if risky:
                    metrics["webhook_review_items"] = int(metrics["webhook_review_items"]) + 1
                    findings.append(
                        _finding(
                            "KUBE-UPGRADE-WEBHOOK-COMPATIBILITY-REVIEW",
                            Severity.MEDIUM,
                            f"Admission webhook requires target-version review: {name}",
                            f"match_policy={match_policy}; timeout_seconds={timeout}; admission_review_versions={admission_versions}",
                            "Verify the webhook handles target-version resources and fields, prefer matchPolicy Equivalent, and test failure behavior before upgrading.",
                            kind="AdmissionWebhook",
                            name=name,
                            confidence=Confidence.MEDIUM,
                        )
                    )

    for crd in _items(payload.get("crds", {})):
        name, _ = _metadata(crd)
        spec = crd.get("spec", {})
        status = crd.get("status", {})
        if not isinstance(spec, dict) or not isinstance(status, dict):
            continue
        versions = spec.get("versions", [])
        declared = (
            {str(version.get("name")) for version in versions if isinstance(version, dict)}
            if isinstance(versions, list)
            else set()
        )
        storage = (
            {str(value) for value in status.get("storedVersions", [])}
            if isinstance(status.get("storedVersions"), list)
            else set()
        )
        missing = sorted(storage - declared)
        storage_versions = (
            [
                str(version.get("name"))
                for version in versions
                if isinstance(version, dict) and version.get("storage") is True
            ]
            if isinstance(versions, list)
            else []
        )
        if missing or len(storage_versions) != 1:
            metrics["crd_storage_issues"] = int(metrics["crd_storage_issues"]) + 1
            findings.append(
                _finding(
                    "KUBE-UPGRADE-CRD-STORAGE-VERSION",
                    Severity.HIGH,
                    f"CRD storage-version state needs remediation: {name}",
                    f"stored_versions={sorted(storage)}; declared_versions={sorted(declared)}; configured_storage_versions={storage_versions}; undeclared_stored_versions={missing}",
                    "Complete CRD storage-version migration and confirm exactly one storage version before upgrading.",
                    kind="CustomResourceDefinition",
                    name=name,
                )
            )

    for api_service in _items(payload.get("api_services", payload.get("apiservices", {}))):
        name, _ = _metadata(api_service)
        status = api_service.get("status", {})
        conditions = status.get("conditions", []) if isinstance(status, dict) else []
        available = (
            any(
                isinstance(condition, dict)
                and condition.get("type") == "Available"
                and condition.get("status") == "True"
                for condition in conditions
            )
            if isinstance(conditions, list)
            else False
        )
        if not available:
            metrics["api_services_unavailable"] = int(metrics["api_services_unavailable"]) + 1
            findings.append(
                _finding(
                    "KUBE-UPGRADE-APISERVICE-UNAVAILABLE",
                    Severity.HIGH,
                    f"Aggregated APIService is unavailable: {name}",
                    "Available condition is not True",
                    "Restore the extension API server and verify API aggregation before upgrading the control plane.",
                    kind="APIService",
                    name=name,
                )
            )

    addons = payload.get("addons", [])
    if isinstance(addons, list):
        metrics["addons_inventoried"] = len([item for item in addons if isinstance(item, dict)])
    return findings, metrics


def _kubectl_args(context: str | None) -> list[str]:
    return ["kubectl", *(["--context", context] if context else [])]


def _json_command(args: list[str], timeout_seconds: int) -> tuple[dict[str, Any], str | None]:
    result = run_command(args, timeout_seconds=timeout_seconds, max_output_chars=10_000_000)
    if not result.succeeded:
        return {}, (result.stderr or result.stdout or "command failed")[:500]
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}, "command returned invalid JSON"
    return (payload if isinstance(payload, dict) else {}), None


def collect_snapshot(context: str | None, timeout_seconds: int) -> dict[str, Any]:
    if executable_path("kubectl") is None:
        raise DependencyUnavailableError("Required executable is unavailable: kubectl")
    base = _kubectl_args(context)
    version, version_error = _json_command([*base, "version", "-o", "json"], timeout_seconds)
    if version_error:
        raise CommandExecutionError(f"Unable to collect Kubernetes version: {version_error}")
    notes: list[str] = []

    text_result = run_command(
        [*base, "api-versions"], timeout_seconds=timeout_seconds, max_output_chars=2_000_000
    )
    api_versions = (
        [line.strip() for line in text_result.stdout.splitlines() if line.strip()]
        if text_result.succeeded
        else []
    )
    if not text_result.succeeded:
        notes.append(f"api-versions: {(text_result.stderr or text_result.stdout)[:300]}")

    collections: dict[str, dict[str, Any]] = {}
    commands = {
        "nodes": [*base, "get", "nodes", "-o", "json"],
        "pdbs": [*base, "get", "poddisruptionbudgets.policy", "-A", "-o", "json"],
        "crds": [*base, "get", "customresourcedefinitions.apiextensions.k8s.io", "-o", "json"],
        "mutating_webhooks": [
            *base,
            "get",
            "mutatingwebhookconfigurations.admissionregistration.k8s.io",
            "-o",
            "json",
        ],
        "validating_webhooks": [
            *base,
            "get",
            "validatingwebhookconfigurations.admissionregistration.k8s.io",
            "-o",
            "json",
        ],
        "api_services": [*base, "get", "apiservices.apiregistration.k8s.io", "-o", "json"],
        "addons_workloads": [
            *base,
            "get",
            "deployments,statefulsets,daemonsets",
            "-n",
            "kube-system",
            "-o",
            "json",
        ],
    }
    for name, command in commands.items():
        payload, error = _json_command(command, timeout_seconds)
        collections[name] = payload
        if error:
            notes.append(f"{name}: {error}")

    addons: list[dict[str, Any]] = []
    for workload in _items(collections.get("addons_workloads", {})):
        name, namespace = _metadata(workload)
        spec = workload.get("spec", {})
        template = spec.get("template", {}) if isinstance(spec, dict) else {}
        pod_spec = template.get("spec", {}) if isinstance(template, dict) else {}
        containers = pod_spec.get("containers", []) if isinstance(pod_spec, dict) else []
        images = (
            [
                str(item.get("image"))
                for item in containers
                if isinstance(item, dict) and item.get("image")
            ]
            if isinstance(containers, list)
            else []
        )
        addons.append(
            {"kind": workload.get("kind"), "name": name, "namespace": namespace, "images": images}
        )

    return {
        "version": {
            "server": version.get("serverVersion", {}),
            "client": version.get("clientVersion", {}),
        },
        "api_versions": api_versions,
        "api_usages": [],
        "nodes": collections.get("nodes", {}),
        "pdbs": collections.get("pdbs", {}),
        "crds": collections.get("crds", {}),
        "mutating_webhooks": collections.get("mutating_webhooks", {}),
        "validating_webhooks": collections.get("validating_webhooks", {}),
        "api_services": collections.get("api_services", {}),
        "addons": addons,
        "collection_notes": [
            *notes,
            "Live discovery cannot prove which deprecated APIs external clients still call; inspect audit logs and manifests in addition to this report.",
        ],
    }


def build_report(
    *,
    target_version: str,
    context: str | None = None,
    snapshot_path: Path | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 60,
    safety_policy: SafetyPolicy | None = None,
    production_acknowledged: bool = False,
) -> Report:
    started = utc_now()
    _version(target_version)
    if snapshot_path is None and safety_policy is not None:
        require_safe_target(
            context or "current-context",
            safety_policy,
            production_acknowledged=production_acknowledged,
        )
    payload = (
        _load_json(snapshot_path) if snapshot_path else collect_snapshot(context, timeout_seconds)
    )
    findings, metrics = analyze_snapshot(payload, target_version=target_version)
    notes = payload.get("collection_notes", [])
    partial = bool(notes) and snapshot_path is None
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=utc_now(),
            target=f"{context or 'offline-snapshot'}->{target_version}",
            partial=partial,
            capabilities=[
                "read-only",
                "offline-snapshot" if snapshot_path else "live-kubectl-collection",
                "version-skew",
                "removed-api-review",
                "node-health",
                "pdb-review",
                "webhook-review",
                "crd-storage-review",
                "addon-inventory",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={
            "metrics": metrics,
            "collection_notes": notes if isinstance(notes, list) else [],
            "known_removed_api_rules": len(REMOVED_APIS),
            "cluster_changes_executed": False,
        },
    )
