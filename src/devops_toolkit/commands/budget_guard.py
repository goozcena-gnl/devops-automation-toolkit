"""Read-only Azure and AWS budget, threshold, forecast, and cost-anomaly guard."""

from __future__ import annotations

import json
from datetime import date
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

TOOL_NAME = "budget-guard"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read budget snapshot: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Budget snapshot root must be an object")
    return payload


def _number(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    if isinstance(value, dict):
        for key in ("amount", "Amount", "value", "Value"):
            if key in value:
                return _number(value[key])
    return None


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    summary: str,
    recommendation: str,
    *,
    provider: str,
    budget_name: str,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="cloud-budget",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Budget coverage, alerting, actual spend, forecast, or cost trend is outside the configured FinOps policy.",
        recommendation=recommendation,
        resource=ResourceRef(
            type="CloudBudget",
            name=budget_name,
            provider=provider,
            identifier=budget_name,
        ),
        evidence=Evidence(summary=summary),
    )


def _normalize_notifications(value: object) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        result: list[dict[str, Any]] = []
        for name, item in value.items():
            if isinstance(item, dict):
                normalized = dict(item)
                normalized.setdefault("name", str(name))
                result.append(normalized)
        return result
    return []


def _notification_threshold(notification: dict[str, Any]) -> float | None:
    for key in ("threshold", "Threshold", "notification_threshold", "NotificationThreshold"):
        if key in notification:
            return _number(notification[key])
    return None


def _notification_enabled(notification: dict[str, Any]) -> bool:
    for key in ("enabled", "Enabled", "NotificationEnabled"):
        if key in notification:
            return bool(notification[key])
    return True


def _has_recipients(notification: dict[str, Any]) -> bool:
    for key in (
        "contactEmails",
        "contact_emails",
        "subscribers",
        "Subscribers",
        "contactGroups",
        "contactRoles",
    ):
        value = notification.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
    return bool(notification.get("recipient_count", 0))


def analyze_budget_payload(
    payload: dict[str, Any],
    *,
    required_thresholds: set[int] | None = None,
    anomaly_ratio: float = 1.5,
    concentration_ratio: float = 0.6,
) -> tuple[list[Finding], dict[str, int | float]]:
    provider = str(payload.get("provider", "unknown")).lower()
    budgets = payload.get("budgets", [])
    if not isinstance(budgets, list):
        raise ConfigurationError("Budget snapshot `budgets` must be a list")
    required = required_thresholds or {50, 80, 100}
    findings: list[Finding] = []
    metrics: dict[str, int | float] = {
        "budgets": len(budgets),
        "missing_thresholds": 0,
        "disabled_notifications": 0,
        "notifications_without_recipients": 0,
        "overspent_budgets": 0,
        "forecast_overspends": 0,
        "cost_anomalies": 0,
        "service_concentration_findings": 0,
    }

    if not budgets:
        findings.append(
            _finding(
                "CLOUD-BUDGET-MISSING",
                Severity.CRITICAL,
                "No cloud budgets were discovered",
                f"provider={provider}; budget_count=0",
                "Create a scoped cost budget with multiple alert thresholds and recipients before expanding cloud usage.",
                provider=provider,
                budget_name="account-or-subscription",
            )
        )

    for budget in budgets:
        if not isinstance(budget, dict):
            continue
        name = str(budget.get("name") or budget.get("BudgetName") or "unnamed-budget")
        amount = _number(budget.get("amount") or budget.get("BudgetLimit"))
        actual = _number(
            budget.get("current_spend")
            or budget.get("actual_spend")
            or budget.get("CurrentSpend")
            or budget.get("CalculatedSpend", {}).get("ActualSpend")
            if isinstance(budget.get("CalculatedSpend"), dict)
            else budget.get("current_spend")
            or budget.get("actual_spend")
            or budget.get("CurrentSpend")
        )
        forecast = _number(
            budget.get("forecast_spend")
            or budget.get("ForecastedSpend")
            or budget.get("CalculatedSpend", {}).get("ForecastedSpend")
            if isinstance(budget.get("CalculatedSpend"), dict)
            else budget.get("forecast_spend") or budget.get("ForecastedSpend")
        )
        if amount is None or amount <= 0:
            findings.append(
                _finding(
                    "CLOUD-BUDGET-INVALID-LIMIT",
                    Severity.HIGH,
                    f"Budget has no positive limit: {name}",
                    f"amount={amount}",
                    "Set a positive amount based on the approved workload forecast and review it after material architecture changes.",
                    provider=provider,
                    budget_name=name,
                )
            )
        notifications = _normalize_notifications(
            budget.get("notifications", budget.get("Notifications", []))
        )
        active_thresholds: set[int] = set()
        for notification in notifications:
            threshold = _notification_threshold(notification)
            enabled = _notification_enabled(notification)
            if threshold is not None and enabled:
                active_thresholds.add(round(threshold))
            if not enabled:
                metrics["disabled_notifications"] = int(metrics["disabled_notifications"]) + 1
                findings.append(
                    _finding(
                        "CLOUD-BUDGET-NOTIFICATION-DISABLED",
                        Severity.MEDIUM,
                        f"Budget notification is disabled: {name}",
                        f"threshold={threshold if threshold is not None else 'unknown'}; enabled=false",
                        "Enable the notification or remove it if it is intentionally obsolete, then validate the remaining escalation path.",
                        provider=provider,
                        budget_name=name,
                    )
                )
            if enabled and not _has_recipients(notification):
                metrics["notifications_without_recipients"] = (
                    int(metrics["notifications_without_recipients"]) + 1
                )
                findings.append(
                    _finding(
                        "CLOUD-BUDGET-NO-RECIPIENTS",
                        Severity.HIGH,
                        f"Budget notification has no recipients: {name}",
                        f"threshold={threshold if threshold is not None else 'unknown'}; recipient_count=0",
                        "Configure an owned distribution list, action group, SNS subscriber, or equivalent escalation target.",
                        provider=provider,
                        budget_name=name,
                    )
                )
        missing = sorted(required - active_thresholds)
        if missing:
            metrics["missing_thresholds"] = int(metrics["missing_thresholds"]) + 1
            findings.append(
                _finding(
                    "CLOUD-BUDGET-MISSING-THRESHOLDS",
                    Severity.HIGH if 100 in missing or 80 in missing else Severity.MEDIUM,
                    f"Budget lacks required alert thresholds: {name}",
                    f"required={','.join(map(str, sorted(required)))}; active={','.join(map(str, sorted(active_thresholds)))}; missing={','.join(map(str, missing))}",
                    "Add progressive actual and forecast notifications so teams can respond before the budget is exhausted.",
                    provider=provider,
                    budget_name=name,
                )
            )
        if amount and actual is not None:
            ratio = actual / amount
            if ratio >= 1.0:
                metrics["overspent_budgets"] = int(metrics["overspent_budgets"]) + 1
                findings.append(
                    _finding(
                        "CLOUD-BUDGET-EXCEEDED",
                        Severity.CRITICAL,
                        f"Budget is exceeded: {name}",
                        f"actual={actual:.2f}; limit={amount:.2f}; utilization_percent={ratio * 100:.1f}",
                        "Investigate the largest cost drivers immediately, freeze nonessential expansion, and document the approved remediation or budget change.",
                        provider=provider,
                        budget_name=name,
                    )
                )
            elif ratio >= 0.8:
                findings.append(
                    _finding(
                        "CLOUD-BUDGET-HIGH-UTILIZATION",
                        Severity.HIGH,
                        f"Budget utilization is high: {name}",
                        f"actual={actual:.2f}; limit={amount:.2f}; utilization_percent={ratio * 100:.1f}",
                        "Review cost drivers and forecast before additional deployments or scaling changes.",
                        provider=provider,
                        budget_name=name,
                    )
                )
        if amount and forecast is not None and forecast > amount:
            metrics["forecast_overspends"] = int(metrics["forecast_overspends"]) + 1
            findings.append(
                _finding(
                    "CLOUD-BUDGET-FORECAST-OVERSPEND",
                    Severity.HIGH,
                    f"Forecast exceeds budget: {name}",
                    f"forecast={forecast:.2f}; limit={amount:.2f}; forecast_percent={forecast / amount * 100:.1f}",
                    "Review the forecast inputs and largest services, then implement approved optimization or update the budget with accountable ownership.",
                    provider=provider,
                    budget_name=name,
                )
            )

    daily_costs = payload.get("daily_costs", [])
    if isinstance(daily_costs, list):
        values: list[float] = []
        for item in daily_costs:
            value = _number(item.get("amount") if isinstance(item, dict) else item)
            if value is not None:
                values.append(value)
        if len(values) >= 8:
            recent_count = min(3, len(values) // 2)
            recent = sum(values[-recent_count:]) / recent_count
            previous_values = values[:-recent_count]
            previous_count = min(7, len(previous_values))
            previous = (
                sum(previous_values[-previous_count:]) / previous_count if previous_count else 0.0
            )
            if previous > 0 and recent / previous >= anomaly_ratio:
                metrics["cost_anomalies"] = int(metrics["cost_anomalies"]) + 1
                findings.append(
                    _finding(
                        "CLOUD-COST-RAPID-INCREASE",
                        Severity.HIGH,
                        "Recent daily cloud spend increased sharply",
                        f"recent_daily_average={recent:.2f}; prior_daily_average={previous:.2f}; ratio={recent / previous:.2f}; threshold={anomaly_ratio:.2f}",
                        "Correlate the increase with deployments, data transfer, scale events, new regions, and anomalous resource creation.",
                        provider=provider,
                        budget_name="cost-trend",
                        confidence=Confidence.MEDIUM,
                    )
                )

    service_costs = payload.get("service_costs", [])
    if isinstance(service_costs, list):
        normalized: list[tuple[str, float]] = []
        for item in service_costs:
            if isinstance(item, dict):
                value = _number(item.get("amount"))
                if value is not None:
                    normalized.append((str(item.get("service", "unknown")), value))
        total = sum(value for _, value in normalized)
        if total > 0:
            for service, value in normalized:
                ratio = value / total
                if ratio >= concentration_ratio:
                    metrics["service_concentration_findings"] = (
                        int(metrics["service_concentration_findings"]) + 1
                    )
                    findings.append(
                        _finding(
                            "CLOUD-COST-SERVICE-CONCENTRATION",
                            Severity.MEDIUM,
                            f"Cloud spend is concentrated in one service: {service}",
                            f"service_cost={value:.2f}; total_cost={total:.2f}; share_percent={ratio * 100:.1f}",
                            "Validate whether the concentration matches architecture expectations and prioritize optimization analysis for this service.",
                            provider=provider,
                            budget_name="service-concentration",
                            confidence=Confidence.MEDIUM,
                        )
                    )
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


def _normalize_azure_budget(item: dict[str, Any]) -> dict[str, Any]:
    properties = item.get("properties", item)
    if not isinstance(properties, dict):
        properties = item
    current = properties.get("currentSpend") or item.get("currentSpend")
    return {
        "name": item.get("name") or properties.get("name"),
        "amount": properties.get("amount"),
        "current_spend": current,
        "notifications": properties.get("notifications", {}),
        "time_grain": properties.get("timeGrain"),
        "category": properties.get("category"),
    }


def collect_azure(subscription: str | None, timeout_seconds: int) -> dict[str, Any]:
    if executable_path("az") is None:
        raise DependencyUnavailableError("Required executable is unavailable: az")
    sub_args = ["--subscription", subscription] if subscription else []
    account = _json_command(["az", "account", "show", *sub_args, "-o", "json"], timeout_seconds)
    budgets_payload = _json_command(
        ["az", "consumption", "budget", "list", *sub_args, "-o", "json"], timeout_seconds
    )
    raw = budgets_payload.get("value", []) if isinstance(budgets_payload, dict) else budgets_payload
    budgets = (
        [_normalize_azure_budget(item) for item in raw if isinstance(item, dict)]
        if isinstance(raw, list)
        else []
    )
    return {
        "provider": "azure",
        "scope": account.get("id", subscription or "current-subscription")
        if isinstance(account, dict)
        else subscription or "current-subscription",
        "budgets": budgets,
        "daily_costs": [],
        "service_costs": [],
        "collection_notes": [
            "Azure CLI budget collection includes configured budgets and current spend when returned by the API; forecast and trend analysis require an enriched snapshot."
        ],
    }


def _month_period() -> tuple[str, str]:
    today = date.today()
    start = today.replace(day=1)
    if today.month == 12:
        next_month = date(today.year + 1, 1, 1)
    else:
        next_month = date(today.year, today.month + 1, 1)
    return start.isoformat(), next_month.isoformat()


def collect_aws(profile: str | None, timeout_seconds: int) -> dict[str, Any]:
    if executable_path("aws") is None:
        raise DependencyUnavailableError("Required executable is unavailable: aws")
    common = (["--profile", profile] if profile else []) + ["--output", "json", "--no-cli-pager"]
    identity = _json_command(["aws", "sts", "get-caller-identity", *common], timeout_seconds)
    account_id = (
        str(identity.get("Account"))
        if isinstance(identity, dict) and identity.get("Account")
        else ""
    )
    if not account_id:
        raise CommandExecutionError("AWS account ID was not returned by sts get-caller-identity")
    budget_response = _json_command(
        ["aws", "budgets", "describe-budgets", "--account-id", account_id, *common], timeout_seconds
    )
    budgets: list[dict[str, Any]] = []
    raw_budgets = budget_response.get("Budgets", []) if isinstance(budget_response, dict) else []
    for item in raw_budgets if isinstance(raw_budgets, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("BudgetName", "unnamed-budget"))
        notifications_response = _json_command(
            [
                "aws",
                "budgets",
                "describe-notifications-for-budget",
                "--account-id",
                account_id,
                "--budget-name",
                name,
                *common,
            ],
            timeout_seconds,
        )
        notifications = (
            notifications_response.get("Notifications", [])
            if isinstance(notifications_response, dict)
            else []
        )
        normalized_notifications: list[dict[str, Any]] = []
        for notification in notifications if isinstance(notifications, list) else []:
            if isinstance(notification, dict):
                normalized_notifications.append(
                    {
                        **notification,
                        "recipient_count": 1,
                    }
                )
        normalized = dict(item)
        normalized["notifications"] = normalized_notifications
        budgets.append(normalized)

    start, end = _month_period()
    usage = _json_command(
        [
            "aws",
            "ce",
            "get-cost-and-usage",
            "--time-period",
            f"Start={start},End={end}",
            "--granularity",
            "DAILY",
            "--metrics",
            "UnblendedCost",
            *common,
        ],
        timeout_seconds,
    )
    daily_costs: list[dict[str, Any]] = []
    if isinstance(usage, dict):
        for result in usage.get("ResultsByTime", []):
            if not isinstance(result, dict):
                continue
            total = result.get("Total", {})
            metric = total.get("UnblendedCost", {}) if isinstance(total, dict) else {}
            if isinstance(metric, dict):
                daily_costs.append(
                    {
                        "date": result.get("TimePeriod", {}).get("Start")
                        if isinstance(result.get("TimePeriod"), dict)
                        else None,
                        "amount": metric.get("Amount"),
                    }
                )
    return {
        "provider": "aws",
        "scope": account_id,
        "budgets": budgets,
        "daily_costs": daily_costs,
        "service_costs": [],
        "collection_notes": [
            "AWS live collection includes budgets, notifications, calculated spend, and month-to-date daily costs. Service concentration and a full-month forecast require an enriched snapshot or additional Cost Explorer permissions."
        ],
    }


def build_report(
    *,
    provider: str,
    snapshot_path: Path | None = None,
    subscription: str | None = None,
    profile: str | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 90,
    required_thresholds: set[int] | None = None,
    anomaly_ratio: float = 1.5,
    concentration_ratio: float = 0.6,
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
    actual_provider = str(payload.get("provider", normalized_provider)).lower()
    if actual_provider != normalized_provider:
        raise ConfigurationError(
            f"Snapshot provider `{actual_provider}` does not match `{normalized_provider}`"
        )
    findings, metrics = analyze_budget_payload(
        payload,
        required_thresholds=required_thresholds,
        anomaly_ratio=anomaly_ratio,
        concentration_ratio=concentration_ratio,
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
                "offline-snapshot" if snapshot_path else "live-cli-collection",
                f"provider:{normalized_provider}",
                "actual-versus-budget",
                "notification-policy",
                "trend-analysis",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={
            "provider": normalized_provider,
            "metrics": metrics,
            "required_thresholds": sorted(required_thresholds or {50, 80, 100}),
            "collection_notes": notes if isinstance(notes, list) else [],
        },
    )
