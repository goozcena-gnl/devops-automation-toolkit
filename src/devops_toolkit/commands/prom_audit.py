"""Read-only Prometheus target, rule, and alert auditor."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from devops_toolkit.core.exceptions import CommandExecutionError, ConfigurationError
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

TOOL_NAME = "prom-audit"


def _resource(kind: str, name: str) -> ResourceRef:
    return ResourceRef(type=kind, name=name, identifier=name)


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    summary: str,
    recommendation: str,
    kind: str,
    name: str,
    *,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="prometheus",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Prometheus read-only API analysis identified an observability reliability concern.",
        recommendation=recommendation,
        resource=_resource(kind, name),
        evidence=Evidence(summary=summary, location=name),
    )


def _read_snapshot(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read Prometheus snapshot: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Prometheus snapshot root must be an object")
    return payload


def _validate_http_url(value: str) -> None:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError("Prometheus URL must be an absolute HTTP or HTTPS URL")


def _request_json(
    base_url: str,
    endpoint: str,
    *,
    timeout_seconds: int,
    bearer_token: str | None,
    ca_file: Path | None,
) -> dict[str, Any]:
    _validate_http_url(base_url)
    url = f"{base_url.rstrip('/')}{endpoint}"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    if bearer_token:
        request.add_header("Authorization", f"Bearer {bearer_token}")
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:  # noqa: S310  # nosec B310
            raw = response.read(10_000_000)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        raise CommandExecutionError(f"Prometheus API request failed for {endpoint}: {exc}") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CommandExecutionError(
            f"Prometheus API returned invalid JSON for {endpoint}: {exc}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("status") != "success":
        error_type = payload.get("errorType") if isinstance(payload, dict) else "unknown"
        raise CommandExecutionError(f"Prometheus API returned status failure: {error_type}")
    data = payload.get("data", {})
    return data if isinstance(data, dict) else {"value": data}


def collect_snapshot(
    base_url: str,
    *,
    timeout_seconds: int,
    bearer_token: str | None,
    ca_file: Path | None,
) -> dict[str, Any]:
    return {
        "base_url": base_url,
        "targets": _request_json(
            base_url,
            "/api/v1/targets?state=any",
            timeout_seconds=timeout_seconds,
            bearer_token=bearer_token,
            ca_file=ca_file,
        ),
        "rules": _request_json(
            base_url,
            "/api/v1/rules",
            timeout_seconds=timeout_seconds,
            bearer_token=bearer_token,
            ca_file=ca_file,
        ),
    }


def analyze_targets(
    data: dict[str, Any],
    *,
    duration_ratio_threshold: float,
    expected_jobs: set[str],
) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    active = data.get("activeTargets", [])
    dropped = data.get("droppedTargets", [])
    metrics = {"active": 0, "down": 0, "unknown": 0, "dropped": 0}
    observed_jobs: set[str] = set()
    if isinstance(dropped, list):
        metrics["dropped"] = len(dropped)
    if not isinstance(active, list):
        return findings, metrics
    for target in active:
        if not isinstance(target, dict):
            continue
        metrics["active"] += 1
        labels = target.get("labels", {})
        discovered = target.get("discoveredLabels", {})
        labels = labels if isinstance(labels, dict) else {}
        discovered = discovered if isinstance(discovered, dict) else {}
        job = str(labels.get("job", discovered.get("job", "unknown")))
        instance = str(labels.get("instance", target.get("scrapeUrl", "unknown")))
        observed_jobs.add(job)
        health = str(target.get("health", "unknown")).lower()
        last_error = str(target.get("lastError", "")).strip()
        if health == "down":
            metrics["down"] += 1
            findings.append(
                _finding(
                    "PROM-TARGET-DOWN",
                    Severity.HIGH,
                    f"Prometheus target is down: {job}/{instance}",
                    f"health=down; last_error={last_error[:500] or 'not reported'}",
                    "Restore endpoint reachability, authentication, TLS trust, or service discovery before relying on related alerts.",
                    "PrometheusTarget",
                    f"{job}/{instance}",
                )
            )
        elif health not in {"up", "unknown"}:
            metrics["unknown"] += 1
            findings.append(
                _finding(
                    "PROM-TARGET-UNHEALTHY",
                    Severity.MEDIUM,
                    f"Prometheus target health is unexpected: {job}/{instance}",
                    f"health={health}; last_error={last_error[:500] or 'not reported'}",
                    "Inspect scrape status and service discovery labels.",
                    "PrometheusTarget",
                    f"{job}/{instance}",
                )
            )
        duration = target.get("scrapeDuration")
        timeout = target.get("scrapeTimeout")
        if isinstance(duration, int | float) and isinstance(timeout, int | float) and timeout > 0:
            ratio = float(duration) / float(timeout)
            if ratio >= duration_ratio_threshold:
                findings.append(
                    _finding(
                        "PROM-SCRAPE-NEAR-TIMEOUT",
                        Severity.MEDIUM,
                        f"Scrape duration is near timeout: {job}/{instance}",
                        f"duration_seconds={duration}; timeout_seconds={timeout}; ratio={ratio:.2f}",
                        "Reduce exporter latency or payload size, or adjust the scrape timeout with evidence.",
                        "PrometheusTarget",
                        f"{job}/{instance}",
                        confidence=Confidence.MEDIUM,
                    )
                )
    for job in sorted(expected_jobs - observed_jobs):
        findings.append(
            _finding(
                "PROM-EXPECTED-JOB-ABSENT",
                Severity.HIGH,
                f"Expected Prometheus job is absent: {job}",
                "No active target reported the configured job label.",
                "Verify service discovery, relabeling, and the expected-target policy.",
                "PrometheusJob",
                job,
            )
        )
    return findings, metrics


def analyze_rules(data: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    groups = data.get("groups", [])
    metrics = {"groups": 0, "rules": 0, "unhealthy": 0, "firing": 0, "pending": 0}
    if not isinstance(groups, list):
        return findings, metrics
    for group in groups:
        if not isinstance(group, dict):
            continue
        metrics["groups"] += 1
        group_name = str(group.get("name", "unknown-group"))
        file_name = str(group.get("file", "unknown-file"))
        rules = group.get("rules", [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            metrics["rules"] += 1
            name = str(rule.get("name", "unknown-rule"))
            health = str(rule.get("health", "unknown")).lower()
            last_error = str(rule.get("lastError", "")).strip()
            if health not in {"ok", "unknown"}:
                metrics["unhealthy"] += 1
                findings.append(
                    _finding(
                        "PROM-RULE-UNHEALTHY",
                        Severity.HIGH,
                        f"Prometheus rule is unhealthy: {name}",
                        f"group={group_name}; file={file_name}; health={health}; last_error={last_error[:500]}",
                        "Correct the PromQL, data dependency, or rule evaluation failure and validate with promtool.",
                        "PrometheusRule",
                        name,
                    )
                )
            rule_type = str(rule.get("type", ""))
            if rule_type == "alerting":
                state = str(rule.get("state", "inactive")).lower()
                labels = rule.get("labels", {})
                annotations = rule.get("annotations", {})
                if state == "firing":
                    metrics["firing"] += 1
                    findings.append(
                        _finding(
                            "PROM-ALERT-FIRING",
                            Severity.MEDIUM,
                            f"Alert rule is firing: {name}",
                            f"group={group_name}; active_alerts={len(rule.get('alerts', [])) if isinstance(rule.get('alerts'), list) else 0}",
                            "Confirm whether the alert is actionable, acknowledged, and linked to an owner or runbook.",
                            "PrometheusAlert",
                            name,
                            confidence=Confidence.HIGH,
                        )
                    )
                elif state == "pending":
                    metrics["pending"] += 1
                if not isinstance(labels, dict) or not labels.get("severity"):
                    findings.append(
                        _finding(
                            "PROM-ALERT-MISSING-SEVERITY",
                            Severity.LOW,
                            f"Alert lacks a severity label: {name}",
                            f"group={group_name}",
                            "Add a consistent severity label for routing and policy evaluation.",
                            "PrometheusAlert",
                            name,
                        )
                    )
                if not isinstance(annotations, dict) or not annotations.get("summary"):
                    findings.append(
                        _finding(
                            "PROM-ALERT-MISSING-SUMMARY",
                            Severity.LOW,
                            f"Alert lacks a summary annotation: {name}",
                            f"group={group_name}",
                            "Add concise summary and runbook annotations for responders.",
                            "PrometheusAlert",
                            name,
                        )
                    )
    return findings, metrics


def validate_rule_files(paths: list[Path], *, timeout_seconds: int) -> list[Finding]:
    if not paths:
        return []
    if executable_path("promtool") is None:
        return [
            _finding(
                "PROM-PROMTOOL-UNAVAILABLE",
                Severity.LOW,
                "promtool is unavailable for local rule validation",
                f"rule_file_count={len(paths)}",
                "Install a compatible promtool version or omit local rule-file validation.",
                "Executable",
                "promtool",
            )
        ]
    result = run_command(
        ["promtool", "check", "rules", *[str(path) for path in paths]],
        timeout_seconds=timeout_seconds,
        max_output_chars=500_000,
    )
    if result.succeeded:
        return []
    return [
        _finding(
            "PROM-RULE-FILE-INVALID",
            Severity.HIGH,
            "Local Prometheus rule validation failed",
            (result.stderr or result.stdout)[:1000],
            "Correct the reported rule syntax or unit-test failure before deployment.",
            "PrometheusRuleFiles",
            ",".join(str(path) for path in paths),
        )
    ]


def build_report(
    *,
    base_url: str | None = None,
    snapshot_path: Path | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 30,
    bearer_token: str | None = None,
    ca_file: Path | None = None,
    expected_jobs: set[str] | None = None,
    duration_ratio_threshold: float = 0.8,
    rule_files: list[Path] | None = None,
) -> Report:
    started = utc_now()
    if snapshot_path is None and base_url is None:
        raise ConfigurationError(
            "Provide --url for live collection or --snapshot for offline analysis"
        )
    snapshot = (
        _read_snapshot(snapshot_path)
        if snapshot_path is not None
        else collect_snapshot(
            str(base_url),
            timeout_seconds=timeout_seconds,
            bearer_token=bearer_token,
            ca_file=ca_file,
        )
    )
    target_data = snapshot.get("targets", {})
    rule_data = snapshot.get("rules", {})
    target_data = target_data if isinstance(target_data, dict) else {}
    rule_data = rule_data if isinstance(rule_data, dict) else {}
    target_findings, target_metrics = analyze_targets(
        target_data,
        duration_ratio_threshold=duration_ratio_threshold,
        expected_jobs=expected_jobs or set(),
    )
    rule_findings, rule_metrics = analyze_rules(rule_data)
    findings = (
        target_findings
        + rule_findings
        + validate_rule_files(rule_files or [], timeout_seconds=timeout_seconds)
    )
    partial = not target_data or not rule_data
    completed = utc_now()
    target = str(snapshot_path.resolve()) if snapshot_path else str(base_url)
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=target,
            partial=partial,
            capabilities=[
                "targets-api",
                "rules-api",
                "expected-job-policy",
                "scrape-timeout-analysis",
                "optional-promtool-validation",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={"targets": target_metrics, "rules": rule_metrics},
    )
