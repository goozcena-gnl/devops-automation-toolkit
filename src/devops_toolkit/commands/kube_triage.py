"""Read-only Kubernetes incident triage and sanitized support bundles."""

from __future__ import annotations

import json
import os
import re
import tempfile
import zipfile
from collections import Counter
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
from devops_toolkit.core.safety import SafetyPolicy, require_safe_target
from devops_toolkit.core.serialization import report_to_json
from devops_toolkit.core.subprocess import executable_path, run_command
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "kube-triage"
WAITING_REASON_SEVERITY: dict[str, Severity] = {
    "CrashLoopBackOff": Severity.HIGH,
    "ImagePullBackOff": Severity.HIGH,
    "ErrImagePull": Severity.HIGH,
    "CreateContainerConfigError": Severity.HIGH,
    "CreateContainerError": Severity.HIGH,
    "RunContainerError": Severity.HIGH,
    "InvalidImageName": Severity.HIGH,
    "ContainerCannotRun": Severity.HIGH,
    "OOMKilled": Severity.HIGH,
}
SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|token|secret|api.?key|client.?secret|access.?key)"
)


def _items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("items", [])
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _metadata(item: dict[str, Any]) -> tuple[str, str]:
    metadata = item.get("metadata", {})
    if not isinstance(metadata, dict):
        return "unknown", "default"
    return str(metadata.get("name", "unknown")), str(metadata.get("namespace", "default"))


def _resource(item: dict[str, Any], kind: str) -> ResourceRef:
    name, namespace = _metadata(item)
    return ResourceRef(type=kind, name=name, namespace=namespace if namespace else None)


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    recommendation: str,
    resource: ResourceRef,
    summary: str,
    *,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="kubernetes",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Kubernetes read-only evidence indicates a workload or cluster health issue.",
        recommendation=recommendation,
        resource=resource,
        evidence=Evidence(summary=summary),
    )


def analyze_nodes(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for node in _items(payload):
        resource = _resource(node, "Node")
        conditions = node.get("status", {}).get("conditions", [])
        if not isinstance(conditions, list):
            continue
        condition_map = {
            str(item.get("type")): str(item.get("status"))
            for item in conditions
            if isinstance(item, dict)
        }
        if condition_map.get("Ready") != "True":
            findings.append(
                _finding(
                    "KUBE-NODE-NOT-READY",
                    Severity.CRITICAL,
                    f"Node `{resource.name}` is not Ready",
                    "Inspect kubelet status, node events, runtime health, networking, disk, and control-plane connectivity.",
                    resource,
                    f"Ready condition is {condition_map.get('Ready', 'missing')}",
                )
            )
        for pressure in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
            if condition_map.get(pressure) == "True":
                findings.append(
                    _finding(
                        "KUBE-NODE-PRESSURE",
                        Severity.HIGH,
                        f"Node `{resource.name}` reports {pressure}",
                        "Inspect node capacity, eviction signals, filesystem usage, process limits, and network health.",
                        resource,
                        f"{pressure}=True",
                    )
                )
    return findings


def _container_findings(pod: dict[str, Any], statuses: Any) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(statuses, list):
        return findings
    resource = _resource(pod, "Pod")
    for status in statuses:
        if not isinstance(status, dict):
            continue
        container_name = str(status.get("name", "unknown"))
        restarts = int(status.get("restartCount", 0) or 0)
        state = status.get("state", {})
        if isinstance(state, dict):
            waiting = state.get("waiting", {})
            if isinstance(waiting, dict):
                reason = str(waiting.get("reason", ""))
                if reason in WAITING_REASON_SEVERITY:
                    findings.append(
                        _finding(
                            "KUBE-CONTAINER-WAITING",
                            WAITING_REASON_SEVERITY[reason],
                            f"Container `{container_name}` is waiting: {reason}",
                            "Inspect pod events, image access, configuration, previous logs, probes, and runtime constraints.",
                            resource,
                            f"container={container_name}; reason={reason}; restarts={restarts}",
                        )
                    )
            terminated = state.get("terminated", {})
            if isinstance(terminated, dict) and terminated.get("reason") == "OOMKilled":
                findings.append(
                    _finding(
                        "KUBE-CONTAINER-OOMKILLED",
                        Severity.HIGH,
                        f"Container `{container_name}` was OOMKilled",
                        "Review memory usage, requests and limits, application memory behavior, and node pressure.",
                        resource,
                        f"container={container_name}; exitCode={terminated.get('exitCode')}",
                    )
                )
        if restarts >= 5:
            findings.append(
                _finding(
                    "KUBE-CONTAINER-RESTARTS",
                    Severity.MEDIUM if restarts < 20 else Severity.HIGH,
                    f"Container `{container_name}` restarted {restarts} times",
                    "Inspect previous logs, termination reasons, probes, dependencies, and resource constraints.",
                    resource,
                    f"container={container_name}; restartCount={restarts}",
                    confidence=Confidence.HIGH,
                )
            )
    return findings


def analyze_pods(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for pod in _items(payload):
        resource = _resource(pod, "Pod")
        status = pod.get("status", {})
        if not isinstance(status, dict):
            continue
        phase = str(status.get("phase", "Unknown"))
        if phase == "Pending":
            findings.append(
                _finding(
                    "KUBE-POD-PENDING",
                    Severity.HIGH,
                    f"Pod `{resource.name}` is Pending",
                    "Review scheduling events, resource availability, affinity, taints, PVC binding, and image pull status.",
                    resource,
                    "Pod phase is Pending",
                )
            )
        elif phase == "Failed":
            findings.append(
                _finding(
                    "KUBE-POD-FAILED",
                    Severity.HIGH,
                    f"Pod `{resource.name}` is Failed",
                    "Inspect termination reasons, controller status, events, and previous logs before restarting or replacing it.",
                    resource,
                    f"reason={status.get('reason', 'unknown')}",
                )
            )
        findings.extend(_container_findings(pod, status.get("initContainerStatuses")))
        findings.extend(_container_findings(pod, status.get("containerStatuses")))
    return findings


def analyze_controllers(kind: str, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for item in _items(payload):
        resource = _resource(item, kind)
        spec = item.get("spec", {})
        status = item.get("status", {})
        if not isinstance(spec, dict) or not isinstance(status, dict):
            continue
        if kind == "Deployment":
            desired = int(spec.get("replicas", 1) or 0)
            available = int(status.get("availableReplicas", 0) or 0)
        elif kind == "StatefulSet":
            desired = int(spec.get("replicas", 1) or 0)
            available = int(status.get("readyReplicas", 0) or 0)
        else:
            desired = int(status.get("desiredNumberScheduled", 0) or 0)
            available = int(status.get("numberAvailable", 0) or 0)
        if available < desired:
            findings.append(
                _finding(
                    "KUBE-CONTROLLER-UNAVAILABLE",
                    Severity.HIGH,
                    f"{kind} `{resource.name}` has unavailable replicas",
                    "Inspect rollout status, child pods, scheduling, probes, image availability, and disruption constraints.",
                    resource,
                    f"desired={desired}; available={available}",
                )
            )
    return findings


def analyze_jobs(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for job in _items(payload):
        status = job.get("status", {})
        if not isinstance(status, dict):
            continue
        failed = int(status.get("failed", 0) or 0)
        if failed:
            resource = _resource(job, "Job")
            findings.append(
                _finding(
                    "KUBE-JOB-FAILED",
                    Severity.HIGH,
                    f"Job `{resource.name}` has failed pods",
                    "Inspect failed pod logs and events, retry policy, deadlines, credentials, and dependent services.",
                    resource,
                    f"failed={failed}; succeeded={status.get('succeeded', 0)}",
                )
            )
    return findings


def analyze_pvcs(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for pvc in _items(payload):
        status = pvc.get("status", {})
        phase = str(status.get("phase", "Unknown")) if isinstance(status, dict) else "Unknown"
        if phase != "Bound":
            resource = _resource(pvc, "PersistentVolumeClaim")
            findings.append(
                _finding(
                    "KUBE-PVC-NOT-BOUND",
                    Severity.HIGH,
                    f"PVC `{resource.name}` is not Bound",
                    "Inspect storage class availability, provisioner health, access modes, capacity, topology, and events.",
                    resource,
                    f"phase={phase}",
                )
            )
    return findings


def analyze_events(payload: dict[str, Any]) -> list[Finding]:
    grouped: Counter[tuple[str, str, str, str]] = Counter()
    for event in _items(payload):
        if str(event.get("type", "")) != "Warning":
            continue
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            involved = {}
        key = (
            str(event.get("reason", "Warning")),
            str(involved.get("kind", "Object")),
            str(involved.get("name", "unknown")),
            str(involved.get("namespace", event.get("metadata", {}).get("namespace", "default"))),
        )
        grouped[key] += int(event.get("count", 1) or 1)
    findings: list[Finding] = []
    for (reason, kind, name, namespace), count in grouped.items():
        findings.append(
            _finding(
                "KUBE-WARNING-EVENT",
                Severity.MEDIUM,
                f"Warning event `{reason}` affects {kind} `{name}`",
                "Inspect the complete event message and correlate it with workload, node, networking, storage, or policy state.",
                ResourceRef(type=kind, name=name, namespace=namespace),
                f"reason={reason}; observed_count={count}",
                confidence=Confidence.MEDIUM,
            )
        )
    return findings


def analyze_endpoints(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in _items(payload):
        name, _ = _metadata(endpoint)
        if name == "kubernetes":
            continue
        subsets = endpoint.get("subsets", [])
        addresses = 0
        if isinstance(subsets, list):
            for subset in subsets:
                if isinstance(subset, dict) and isinstance(subset.get("addresses"), list):
                    addresses += len(subset["addresses"])
        if addresses == 0:
            resource = _resource(endpoint, "Endpoints")
            findings.append(
                _finding(
                    "KUBE-ENDPOINTS-EMPTY",
                    Severity.MEDIUM,
                    f"Endpoints `{resource.name}` has no ready addresses",
                    "Verify the matching Service selector, pod readiness, target ports, and endpoint controller state.",
                    resource,
                    "ready_addresses=0",
                    confidence=Confidence.HIGH,
                )
            )
    return findings


def sanitize_kubernetes_payload(value: Any, *, parent_key: str = "") -> Any:
    redactor = Redactor()
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        kind = str(value.get("kind", ""))
        for key, child in value.items():
            if key == "managedFields":
                continue
            should_redact = (
                (kind == "Secret" and key in {"data", "stringData"})
                or bool(SENSITIVE_KEY.search(str(key)))
                or (key == "value" and parent_key == "env")
                or key == "kubectl.kubernetes.io/last-applied-configuration"
            )
            if should_redact:
                result[key] = "[REDACTED]"
            else:
                result[key] = sanitize_kubernetes_payload(child, parent_key=str(key))
        return result
    if isinstance(value, list):
        return [sanitize_kubernetes_payload(item, parent_key=parent_key) for item in value]
    if isinstance(value, str):
        return redactor.redact(value)
    return value


def _kubectl_json(
    args: list[str], *, context: str, timeout_seconds: int
) -> tuple[dict[str, Any], str | None]:
    result = run_command(
        ["kubectl", "--context", context, *args, "-o", "json"],
        timeout_seconds=timeout_seconds,
        max_output_chars=10_000_000,
        sanitize_output=False,
    )
    if result.timed_out:
        return {}, "command timed out"
    if result.returncode != 0:
        return {}, Redactor().redact(result.stderr or result.stdout)[:500]
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}, "kubectl returned invalid JSON"
    return payload if isinstance(payload, dict) else {}, None


def resolve_context(context: str | None, timeout_seconds: int) -> str:
    if executable_path("kubectl") is None:
        raise DependencyUnavailableError("Required executable is unavailable: kubectl")
    contexts_result = run_command(
        ["kubectl", "config", "get-contexts", "-o", "name"], timeout_seconds=timeout_seconds
    )
    if not contexts_result.succeeded:
        raise ConfigurationError("Unable to list Kubernetes contexts")
    contexts = [line.strip() for line in contexts_result.stdout.splitlines() if line.strip()]
    if context:
        if context not in contexts:
            raise ConfigurationError(f"Kubernetes context does not exist: {context}")
        return context
    if len(contexts) > 1:
        raise ConfigurationError("Multiple Kubernetes contexts exist; provide --context explicitly")
    if len(contexts) == 1:
        return contexts[0]
    current = run_command(["kubectl", "config", "current-context"], timeout_seconds=timeout_seconds)
    if current.succeeded and current.stdout.strip():
        return current.stdout.strip()
    raise ConfigurationError("No Kubernetes context is configured")


def collect_cluster(
    context: str,
    *,
    namespace: str = "default",
    all_namespaces: bool = False,
    timeout_seconds: int = 30,
) -> tuple[dict[str, dict[str, Any]], dict[str, str], bool]:
    collections: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    resources = {
        "nodes": ["get", "nodes"],
        "pods": ["get", "pods"],
        "deployments": ["get", "deployments"],
        "statefulsets": ["get", "statefulsets"],
        "daemonsets": ["get", "daemonsets"],
        "jobs": ["get", "jobs"],
        "pvcs": ["get", "persistentvolumeclaims"],
        "events": ["get", "events"],
        "endpoints": ["get", "endpoints"],
    }
    for name, args in resources.items():
        scoped_args = list(args)
        if name != "nodes":
            scoped_args.extend(["-A"] if all_namespaces else ["-n", namespace])
        payload, error = _kubectl_json(
            scoped_args, context=context, timeout_seconds=timeout_seconds
        )
        if error:
            errors[name] = error
        else:
            collections[name] = payload
    return collections, errors, bool(errors)


def analyze_collection(collections: dict[str, dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(analyze_nodes(collections.get("nodes", {})))
    findings.extend(analyze_pods(collections.get("pods", {})))
    findings.extend(analyze_controllers("Deployment", collections.get("deployments", {})))
    findings.extend(analyze_controllers("StatefulSet", collections.get("statefulsets", {})))
    findings.extend(analyze_controllers("DaemonSet", collections.get("daemonsets", {})))
    findings.extend(analyze_jobs(collections.get("jobs", {})))
    findings.extend(analyze_pvcs(collections.get("pvcs", {})))
    findings.extend(analyze_events(collections.get("events", {})))
    findings.extend(analyze_endpoints(collections.get("endpoints", {})))
    return findings


def build_report(
    *,
    context: str | None = None,
    namespace: str = "default",
    all_namespaces: bool = False,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 30,
    safety_policy: SafetyPolicy | None = None,
    production_acknowledged: bool = False,
) -> tuple[Report, dict[str, dict[str, Any]]]:
    started = utc_now()
    resolved_context = resolve_context(context, timeout_seconds)
    require_safe_target(
        resolved_context,
        safety_policy or SafetyPolicy(),
        production_acknowledged=production_acknowledged,
    )
    collections, errors, partial = collect_cluster(
        resolved_context,
        namespace=namespace,
        all_namespaces=all_namespaces,
        timeout_seconds=timeout_seconds,
    )
    findings = analyze_collection(collections)
    for resource_name, error in errors.items():
        findings.append(
            _finding(
                "KUBE-COLLECTION-INCOMPLETE",
                Severity.MEDIUM,
                f"Unable to collect Kubernetes resource `{resource_name}`",
                "Verify RBAC permissions, API availability, selected context, namespace scope, and network connectivity.",
                ResourceRef(type="Collection", name=resource_name),
                error,
                confidence=Confidence.HIGH,
            )
        )
    completed = utc_now()
    report = Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=resolved_context,
            partial=partial,
            capabilities=[
                "nodes",
                "workloads",
                "events",
                "storage",
                "endpoints",
                "sanitized-bundle",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={
            "scope": {"namespace": namespace, "all_namespaces": all_namespaces},
            "collection_errors": errors,
            "resource_counts": {
                name: len(_items(payload)) for name, payload in collections.items()
            },
        },
    )
    return report, collections


def write_sanitized_bundle(
    path: Path, report: Report, collections: dict[str, dict[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.json", report_to_json(report))
            for name, payload in collections.items():
                sanitized = sanitize_kubernetes_payload(payload)
                archive.writestr(
                    f"evidence/{name}.json",
                    json.dumps(sanitized, indent=2, sort_keys=False) + "\n",
                )
        temporary.chmod(0o600)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
