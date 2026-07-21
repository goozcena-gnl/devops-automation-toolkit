"""Read-only Kubernetes requests, limits, and current-usage rightsizing auditor."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from devops_toolkit.commands.kube_triage import resolve_context
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

TOOL_NAME = "kube-rightsize"
CPU_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)?)(n|u|m)?$")
MEMORY_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([EPTGMK]i?|m|k)?$")
MEMORY_MULTIPLIERS = {
    None: 1.0,
    "k": 1_000.0,
    "m": 0.001,
    "K": 1_000.0,
    "M": 1_000_000.0,
    "G": 1_000_000_000.0,
    "T": 1_000_000_000_000.0,
    "P": 1_000_000_000_000_000.0,
    "E": 1_000_000_000_000_000_000.0,
    "Ki": 1024.0,
    "Mi": 1024.0**2,
    "Gi": 1024.0**3,
    "Ti": 1024.0**4,
    "Pi": 1024.0**5,
    "Ei": 1024.0**6,
}


def parse_cpu(value: object) -> float | None:
    """Return CPU quantity in cores."""

    if value is None or value == "":
        return None
    match = CPU_PATTERN.fullmatch(str(value).strip())
    if not match:
        return None
    amount = float(match.group(1))
    suffix = match.group(2)
    return amount * {None: 1.0, "m": 1e-3, "u": 1e-6, "n": 1e-9}[suffix]


def parse_memory(value: object) -> float | None:
    """Return memory quantity in bytes."""

    if value is None or value == "":
        return None
    match = MEMORY_PATTERN.fullmatch(str(value).strip())
    if not match:
        return None
    suffix = match.group(2)
    return float(match.group(1)) * MEMORY_MULTIPLIERS[suffix]


def _format_cpu(value: float) -> str:
    return f"{max(1, round(value * 1000))}m"


def _format_memory(value: float) -> str:
    mebibytes = max(1, round(value / (1024.0**2)))
    return f"{mebibytes}Mi"


def _items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("items", [])
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _read_snapshot(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read Kubernetes rightsizing snapshot: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Kubernetes rightsizing snapshot root must be an object")
    return payload


def _kubectl_json(args: list[str], *, context: str, timeout_seconds: int) -> dict[str, Any]:
    if executable_path("kubectl") is None:
        raise DependencyUnavailableError("Required executable is unavailable: kubectl")
    result = run_command(
        ["kubectl", "--context", context, *args, "-o", "json"],
        timeout_seconds=timeout_seconds,
        max_output_chars=20_000_000,
    )
    if not result.succeeded:
        raise CommandExecutionError(
            f"kubectl collection failed: {(result.stderr or result.stdout)[:1000]}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CommandExecutionError(f"kubectl returned invalid JSON: {exc}") from exc
    return payload if isinstance(payload, dict) else {}


def collect_snapshot(
    context: str,
    *,
    namespace: str,
    all_namespaces: bool,
    timeout_seconds: int,
) -> dict[str, Any]:
    scope = ["-A"] if all_namespaces else ["-n", namespace]
    pods = _kubectl_json(["get", "pods", *scope], context=context, timeout_seconds=timeout_seconds)
    if executable_path("kubectl") is None:
        raise DependencyUnavailableError("Required executable is unavailable: kubectl")
    metrics_result = run_command(
        [
            "kubectl",
            "--context",
            context,
            "get",
            "--raw",
            "/apis/metrics.k8s.io/v1beta1/pods",
        ],
        timeout_seconds=timeout_seconds,
        max_output_chars=20_000_000,
    )
    metrics: dict[str, Any] = {}
    metrics_error: str | None = None
    if metrics_result.succeeded:
        try:
            decoded = json.loads(metrics_result.stdout)
            metrics = decoded if isinstance(decoded, dict) else {}
        except json.JSONDecodeError:
            metrics_error = "Metrics API returned invalid JSON"
    else:
        metrics_error = (metrics_result.stderr or metrics_result.stdout)[:1000]
    return {"pods": pods, "metrics": metrics, "metrics_error": metrics_error}


def _owner(pod: dict[str, Any]) -> tuple[str, str]:
    metadata = pod.get("metadata", {})
    if not isinstance(metadata, dict):
        return "Pod", "unknown"
    owners = metadata.get("ownerReferences", [])
    if isinstance(owners, list) and owners:
        owner = owners[0]
        if isinstance(owner, dict):
            return str(owner.get("kind", "Pod")), str(
                owner.get("name", metadata.get("name", "unknown"))
            )
    return "Pod", str(metadata.get("name", "unknown"))


def _metrics_index(payload: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in _items(payload):
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        namespace = str(metadata.get("namespace", "default"))
        pod_name = str(metadata.get("name", "unknown"))
        containers = item.get("containers", [])
        if not isinstance(containers, list):
            continue
        for container in containers:
            if isinstance(container, dict):
                index[(namespace, pod_name, str(container.get("name", "unknown")))] = container
    return index


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    summary: str,
    recommendation: str,
    namespace: str,
    workload: str,
    kind: str,
    *,
    confidence: Confidence = Confidence.MEDIUM,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="kubernetes-resources",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Resource request, limit, and current-usage analysis identified a capacity or reliability concern.",
        recommendation=recommendation,
        resource=ResourceRef(type=kind, name=workload, namespace=namespace),
        evidence=Evidence(summary=summary),
    )


def analyze_snapshot(
    snapshot: dict[str, Any],
    *,
    overrequest_ratio: float = 0.25,
    high_usage_ratio: float = 0.85,
    recommendation_headroom: float = 1.25,
) -> tuple[list[Finding], list[dict[str, Any]], dict[str, int]]:
    pods = snapshot.get("pods", {})
    metrics_payload = snapshot.get("metrics", {})
    pods = pods if isinstance(pods, dict) else {}
    metrics_payload = metrics_payload if isinstance(metrics_payload, dict) else {}
    usage_index = _metrics_index(metrics_payload)
    findings: list[Finding] = []
    previews: list[dict[str, Any]] = []
    counters: defaultdict[str, int] = defaultdict(int)
    for pod in _items(pods):
        metadata = pod.get("metadata", {})
        spec = pod.get("spec", {})
        if not isinstance(metadata, dict) or not isinstance(spec, dict):
            continue
        namespace = str(metadata.get("namespace", "default"))
        pod_name = str(metadata.get("name", "unknown"))
        kind, workload = _owner(pod)
        containers = spec.get("containers", [])
        if not isinstance(containers, list):
            continue
        for container in containers:
            if not isinstance(container, dict):
                continue
            counters["containers"] += 1
            name = str(container.get("name", "unknown"))
            resources = container.get("resources", {})
            resources = resources if isinstance(resources, dict) else {}
            resource_requests = resources.get("requests", {})
            limits = resources.get("limits", {})
            resource_requests = resource_requests if isinstance(resource_requests, dict) else {}
            limits = limits if isinstance(limits, dict) else {}
            cpu_request = parse_cpu(resource_requests.get("cpu"))
            memory_request = parse_memory(resource_requests.get("memory"))
            cpu_limit = parse_cpu(limits.get("cpu"))
            memory_limit = parse_memory(limits.get("memory"))
            usage = usage_index.get((namespace, pod_name, name))
            cpu_usage = None
            memory_usage = None
            if isinstance(usage, dict):
                usage_values = usage.get("usage", {})
                if isinstance(usage_values, dict):
                    cpu_usage = parse_cpu(usage_values.get("cpu"))
                    memory_usage = parse_memory(usage_values.get("memory"))
                    counters["containers_with_metrics"] += 1
            if cpu_request is None or memory_request is None:
                counters["missing_requests"] += 1
                missing = [
                    resource
                    for resource, value in (("cpu", cpu_request), ("memory", memory_request))
                    if value is None
                ]
                findings.append(
                    _finding(
                        "KUBE-RESOURCES-MISSING-REQUEST",
                        Severity.MEDIUM,
                        f"Container lacks resource requests: {namespace}/{workload}/{name}",
                        f"missing={missing}; pod={pod_name}",
                        "Set evidence-based CPU and memory requests so scheduling and autoscaling have reliable inputs.",
                        namespace,
                        workload,
                        kind,
                        confidence=Confidence.HIGH,
                    )
                )
            if cpu_limit is None or memory_limit is None:
                counters["missing_limits"] += 1
                missing = [
                    resource
                    for resource, value in (("cpu", cpu_limit), ("memory", memory_limit))
                    if value is None
                ]
                findings.append(
                    _finding(
                        "KUBE-RESOURCES-MISSING-LIMIT",
                        Severity.LOW,
                        f"Container lacks resource limits: {namespace}/{workload}/{name}",
                        f"missing={missing}; pod={pod_name}",
                        "Decide explicitly whether limits are required by workload behavior and namespace policy.",
                        namespace,
                        workload,
                        kind,
                        confidence=Confidence.HIGH,
                    )
                )
            recommendation: dict[str, str] = {}
            if cpu_usage is not None:
                recommendation["cpu_request"] = _format_cpu(cpu_usage * recommendation_headroom)
                if cpu_request and cpu_usage / cpu_request < overrequest_ratio:
                    counters["overrequested_cpu"] += 1
                    findings.append(
                        _finding(
                            "KUBE-CPU-OVERREQUESTED",
                            Severity.LOW,
                            f"CPU request may be oversized: {namespace}/{workload}/{name}",
                            f"usage_cores={cpu_usage:.6f}; request_cores={cpu_request:.6f}; ratio={cpu_usage / cpu_request:.2f}",
                            "Review a longer observation window before reducing the CPU request.",
                            namespace,
                            workload,
                            kind,
                            confidence=Confidence.LOW,
                        )
                    )
                if cpu_request and cpu_usage / cpu_request >= high_usage_ratio:
                    counters["high_cpu"] += 1
                    findings.append(
                        _finding(
                            "KUBE-CPU-REQUEST-PRESSURE",
                            Severity.MEDIUM,
                            f"CPU usage is near or above request: {namespace}/{workload}/{name}",
                            f"usage_cores={cpu_usage:.6f}; request_cores={cpu_request:.6f}; ratio={cpu_usage / cpu_request:.2f}",
                            "Review sustained CPU usage, throttling, HPA behavior, and request headroom.",
                            namespace,
                            workload,
                            kind,
                            confidence=Confidence.LOW,
                        )
                    )
                if cpu_limit and cpu_usage / cpu_limit >= high_usage_ratio:
                    counters["cpu_limit_risk"] += 1
                    findings.append(
                        _finding(
                            "KUBE-CPU-LIMIT-RISK",
                            Severity.MEDIUM,
                            f"CPU usage is near the limit: {namespace}/{workload}/{name}",
                            f"usage_cores={cpu_usage:.6f}; limit_cores={cpu_limit:.6f}; ratio={cpu_usage / cpu_limit:.2f}",
                            "Inspect throttling metrics and sustained percentile usage before changing the CPU limit.",
                            namespace,
                            workload,
                            kind,
                            confidence=Confidence.LOW,
                        )
                    )
            if memory_usage is not None:
                recommendation["memory_request"] = _format_memory(
                    memory_usage * recommendation_headroom
                )
                if memory_request and memory_usage / memory_request < overrequest_ratio:
                    counters["overrequested_memory"] += 1
                    findings.append(
                        _finding(
                            "KUBE-MEMORY-OVERREQUESTED",
                            Severity.LOW,
                            f"Memory request may be oversized: {namespace}/{workload}/{name}",
                            f"usage_bytes={memory_usage:.0f}; request_bytes={memory_request:.0f}; ratio={memory_usage / memory_request:.2f}",
                            "Review peak and percentile memory usage across a longer window before reducing the request.",
                            namespace,
                            workload,
                            kind,
                            confidence=Confidence.LOW,
                        )
                    )
                if memory_limit and memory_usage / memory_limit >= high_usage_ratio:
                    counters["memory_limit_risk"] += 1
                    findings.append(
                        _finding(
                            "KUBE-MEMORY-LIMIT-RISK",
                            Severity.HIGH,
                            f"Memory usage is near the limit: {namespace}/{workload}/{name}",
                            f"usage_bytes={memory_usage:.0f}; limit_bytes={memory_limit:.0f}; ratio={memory_usage / memory_limit:.2f}",
                            "Inspect peak memory behavior and OOM history before increasing the limit or fixing the application.",
                            namespace,
                            workload,
                            kind,
                            confidence=Confidence.MEDIUM,
                        )
                    )
            if recommendation:
                previews.append(
                    {
                        "namespace": namespace,
                        "workload_kind": kind,
                        "workload": workload,
                        "container": name,
                        "evidence_scope": "current Metrics API sample",
                        "suggested_requests": recommendation,
                    }
                )
    return findings, previews, dict(counters)


def build_report(
    *,
    context: str | None = None,
    namespace: str = "default",
    all_namespaces: bool = False,
    snapshot_path: Path | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 30,
    safety_policy: SafetyPolicy | None = None,
    production_acknowledged: bool = False,
    include_patch_preview: bool = False,
    overrequest_ratio: float = 0.25,
    high_usage_ratio: float = 0.85,
) -> Report:
    started = utc_now()
    if snapshot_path is not None:
        snapshot = _read_snapshot(snapshot_path)
        resolved_context = str(snapshot.get("context", snapshot_path.resolve()))
    else:
        resolved_context = resolve_context(context, timeout_seconds)
        require_safe_target(
            resolved_context,
            safety_policy or SafetyPolicy(),
            production_acknowledged=production_acknowledged,
        )
        snapshot = collect_snapshot(
            resolved_context,
            namespace=namespace,
            all_namespaces=all_namespaces,
            timeout_seconds=timeout_seconds,
        )
    findings, previews, counters = analyze_snapshot(
        snapshot,
        overrequest_ratio=overrequest_ratio,
        high_usage_ratio=high_usage_ratio,
    )
    metrics_error = snapshot.get("metrics_error")
    partial = not isinstance(snapshot.get("metrics"), dict) or not snapshot.get("metrics")
    if metrics_error or partial:
        findings.append(
            _finding(
                "KUBE-METRICS-UNAVAILABLE",
                Severity.MEDIUM,
                "Kubernetes Metrics API data is unavailable or incomplete",
                f"error={str(metrics_error or 'no metrics returned')[:500]}",
                "Install or repair Metrics Server, or provide a longer-window Prometheus source before making rightsizing changes.",
                namespace,
                "metrics-api",
                "APIService",
                confidence=Confidence.HIGH,
            )
        )
    completed = utc_now()
    extensions: dict[str, Any] = {
        "scope": {"namespace": namespace, "all_namespaces": all_namespaces},
        "metrics": counters,
        "recommendation_warning": "Current Metrics API samples are insufficient for automatic resizing; validate with longer-window percentile data.",
    }
    if include_patch_preview:
        extensions["patch_preview"] = previews
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=resolved_context,
            partial=partial,
            capabilities=[
                "requests-and-limits",
                "metrics-api-current-usage",
                "confidence-labelled-recommendations",
                "read-only-patch-preview",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions=extensions,
    )
