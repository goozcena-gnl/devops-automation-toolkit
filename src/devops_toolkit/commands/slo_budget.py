"""Deterministic SLO compliance, error-budget, and burn-rate calculator."""

from __future__ import annotations

import csv
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

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
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "slo-budget"


@dataclass(frozen=True)
class Sample:
    timestamp: float
    good: float
    total: float


@dataclass(frozen=True)
class BurnWindow:
    name: str
    points: int
    threshold: float
    severity: Severity


def _parse_timestamp(value: object, fallback: float) -> float:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        try:
            return float(stripped)
        except ValueError:
            try:
                return datetime.fromisoformat(stripped.replace("Z", "+00:00")).timestamp()
            except ValueError as exc:
                raise ConfigurationError(f"Invalid SLO sample timestamp: {value}") from exc
    return fallback


def _validated_sample(timestamp: object, good: object, total: object, index: int) -> Sample:
    try:
        good_value = float(str(good))
        total_value = float(str(total))
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"SLO sample {index} has non-numeric good/total values") from exc
    if total_value < 0 or good_value < 0 or good_value > total_value:
        raise ConfigurationError(
            f"SLO sample {index} must satisfy 0 <= good <= total; got {good_value}/{total_value}"
        )
    return Sample(_parse_timestamp(timestamp, float(index)), good_value, total_value)


def load_samples(path: Path) -> list[Sample]:
    suffix = path.suffix.lower()
    try:
        if suffix == ".csv":
            with path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            return [
                _validated_sample(
                    row.get("timestamp", index), row.get("good"), row.get("total"), index
                )
                for index, row in enumerate(rows)
            ]
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, csv.Error, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read SLO sample data: {exc}") from exc
    raw_samples = payload.get("samples", []) if isinstance(payload, dict) else payload
    if not isinstance(raw_samples, list):
        raise ConfigurationError("SLO JSON data must be a list or an object with `samples`")
    samples: list[Sample] = []
    for index, item in enumerate(raw_samples):
        if not isinstance(item, dict):
            raise ConfigurationError(f"SLO sample {index} must be an object")
        samples.append(
            _validated_sample(
                item.get("timestamp", index), item.get("good"), item.get("total"), index
            )
        )
    return samples


def _validate_http_url(value: str) -> None:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError("Prometheus URL must be an absolute HTTP or HTTPS URL")


def _prometheus_query_range(
    base_url: str,
    query: str,
    *,
    start: str,
    end: str,
    step: str,
    timeout_seconds: int,
    bearer_token: str | None,
    ca_file: Path | None,
) -> dict[float, float]:
    params = urllib.parse.urlencode({"query": query, "start": start, "end": end, "step": step})
    request = urllib.request.Request(  # noqa: S310
        f"{base_url.rstrip('/')}/api/v1/query_range?{params}",
        headers={"Accept": "application/json"},
    )
    if bearer_token:
        request.add_header("Authorization", f"Bearer {bearer_token}")
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:  # noqa: S310  # nosec B310
            raw = response.read(20_000_000)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        raise CommandExecutionError(f"Prometheus SLO query failed: {exc}") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CommandExecutionError(f"Prometheus SLO query returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise CommandExecutionError("Prometheus SLO query returned a non-success response")
    data = payload.get("data", {})
    result = data.get("result", []) if isinstance(data, dict) else []
    if not isinstance(result, list):
        raise CommandExecutionError("Prometheus SLO query result must be a list")
    aggregated: dict[float, float] = {}
    for series in result:
        if not isinstance(series, dict):
            continue
        values = series.get("values", [])
        if not isinstance(values, list):
            continue
        for pair in values:
            if not isinstance(pair, list) or len(pair) != 2:
                continue
            try:
                timestamp = float(pair[0])
                value = float(pair[1])
            except (TypeError, ValueError):
                continue
            aggregated[timestamp] = aggregated.get(timestamp, 0.0) + value
    return aggregated


def collect_prometheus_samples(
    config: dict[str, Any],
    *,
    timeout_seconds: int,
    bearer_token: str | None,
    ca_file: Path | None,
) -> list[Sample]:
    required = {"url", "good_query", "total_query", "start", "end", "step"}
    missing = sorted(required - set(config))
    if missing:
        raise ConfigurationError(f"Prometheus SLO configuration is missing: {', '.join(missing)}")
    base_url = str(config["url"])
    start = str(config["start"])
    end = str(config["end"])
    step = str(config["step"])
    good = _prometheus_query_range(
        base_url,
        str(config["good_query"]),
        start=start,
        end=end,
        step=step,
        timeout_seconds=timeout_seconds,
        bearer_token=bearer_token,
        ca_file=ca_file,
    )
    total = _prometheus_query_range(
        base_url,
        str(config["total_query"]),
        start=start,
        end=end,
        step=step,
        timeout_seconds=timeout_seconds,
        bearer_token=bearer_token,
        ca_file=ca_file,
    )
    timestamps = sorted(set(good) | set(total))
    return [
        _validated_sample(timestamp, good.get(timestamp, 0.0), total.get(timestamp, 0.0), index)
        for index, timestamp in enumerate(timestamps)
    ]


def load_spec(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to read SLO specification: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("SLO specification root must be an object")
    return payload


def _burn_rate(samples: list[Sample], objective: float) -> float | None:
    total = sum(item.total for item in samples)
    if total <= 0:
        return None
    good = sum(item.good for item in samples)
    observed_error_rate = max(0.0, 1.0 - (good / total))
    allowed_error_rate = 1.0 - objective
    if allowed_error_rate <= 0:
        return None
    return observed_error_rate / allowed_error_rate


def _burn_windows(spec: dict[str, Any]) -> list[BurnWindow]:
    raw = spec.get("burn_windows")
    if raw is None:
        return [
            BurnWindow("fast", 12, 14.4, Severity.CRITICAL),
            BurnWindow("slow", 72, 6.0, Severity.HIGH),
        ]
    if not isinstance(raw, list):
        raise ConfigurationError("burn_windows must be a list")
    windows: list[BurnWindow] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigurationError(f"burn_windows[{index}] must be an object")
        try:
            windows.append(
                BurnWindow(
                    name=str(item["name"]),
                    points=int(item["points"]),
                    threshold=float(item["threshold"]),
                    severity=Severity(str(item.get("severity", "high"))),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(f"Invalid burn window at index {index}: {exc}") from exc
    return windows


def analyze_slo(
    name: str,
    objective: float,
    samples: list[Sample],
    windows: list[BurnWindow],
) -> tuple[list[Finding], dict[str, Any]]:
    if not 0 < objective < 1:
        raise ConfigurationError("SLO objective must be greater than 0 and less than 1")
    findings: list[Finding] = []
    samples = sorted(samples, key=lambda item: item.timestamp)
    total = sum(item.total for item in samples)
    good = sum(item.good for item in samples)
    bad = total - good
    if total <= 0:
        findings.append(
            Finding(
                id="SLO-NO-DATA",
                tool=TOOL_NAME,
                category="slo",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"No usable SLI data for {name}",
                recommendation="Verify the data source, query range, and distinction between no data and zero failures.",
                resource=ResourceRef(type="SLO", name=name),
                evidence=Evidence(summary=f"sample_count={len(samples)}; total_events={total}"),
            )
        )
        return findings, {
            "name": name,
            "objective": objective,
            "sample_count": len(samples),
            "total": total,
            "good": good,
            "bad": bad,
            "compliance": None,
            "error_budget_remaining": None,
        }
    compliance = good / total
    allowed_bad = total * (1.0 - objective)
    consumed = bad / allowed_bad if allowed_bad > 0 else float("inf")
    remaining = 1.0 - consumed
    overall_burn = _burn_rate(samples, objective)
    if compliance < objective:
        findings.append(
            Finding(
                id="SLO-OBJECTIVE-MISSED",
                tool=TOOL_NAME,
                category="slo",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"SLO objective missed: {name}",
                recommendation="Prioritize reliability work, freeze risky changes when policy requires it, and inspect the dominant failure source.",
                resource=ResourceRef(type="SLO", name=name),
                evidence=Evidence(
                    summary=f"objective={objective:.6f}; compliance={compliance:.6f}; bad={bad:.3f}; total={total:.3f}"
                ),
            )
        )
    if remaining <= 0:
        findings.append(
            Finding(
                id="SLO-ERROR-BUDGET-EXHAUSTED",
                tool=TOOL_NAME,
                category="slo",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title=f"Error budget exhausted: {name}",
                recommendation="Apply the organization error-budget policy and focus on restoring sustainable reliability.",
                resource=ResourceRef(type="SLO", name=name),
                evidence=Evidence(
                    summary=f"budget_consumed={consumed:.3f}; budget_remaining={remaining:.3f}"
                ),
            )
        )
    burn_metrics: dict[str, float | None] = {}
    for window in windows:
        selected = samples[-window.points :] if window.points > 0 else samples
        burn = _burn_rate(selected, objective)
        burn_metrics[window.name] = burn
        if burn is not None and burn >= window.threshold:
            findings.append(
                Finding(
                    id="SLO-BURN-RATE-EXCEEDED",
                    tool=TOOL_NAME,
                    category="slo-burn-rate",
                    severity=window.severity,
                    confidence=Confidence.HIGH,
                    title=f"{window.name.title()} burn-rate threshold exceeded: {name}",
                    recommendation="Investigate the current failure mode and use the paired burn windows to avoid reacting to isolated noise.",
                    resource=ResourceRef(type="SLO", name=name),
                    evidence=Evidence(
                        summary=f"window_points={len(selected)}; burn_rate={burn:.3f}; threshold={window.threshold:.3f}"
                    ),
                )
            )
    metrics: dict[str, Any] = {
        "name": name,
        "objective": objective,
        "sample_count": len(samples),
        "period_start": datetime.fromtimestamp(samples[0].timestamp, UTC).isoformat(),
        "period_end": datetime.fromtimestamp(samples[-1].timestamp, UTC).isoformat(),
        "total": total,
        "good": good,
        "bad": bad,
        "compliance": compliance,
        "allowed_bad": allowed_bad,
        "error_budget_consumed": consumed,
        "error_budget_remaining": remaining,
        "overall_burn_rate": overall_burn,
        "burn_windows": burn_metrics,
    }
    return findings, metrics


def build_report(
    spec_path: Path,
    *,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 30,
    bearer_token: str | None = None,
    ca_file: Path | None = None,
) -> Report:
    started = utc_now()
    spec = load_spec(spec_path)
    name = str(spec.get("name", spec_path.stem))
    try:
        objective = float(spec["objective"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError("SLO specification requires a numeric `objective`") from exc
    data_file = spec.get("data_file")
    prometheus = spec.get("prometheus")
    if data_file is not None and prometheus is not None:
        raise ConfigurationError("Configure either data_file or prometheus, not both")
    if data_file is not None:
        resolved = (spec_path.parent / str(data_file)).resolve()
        samples = load_samples(resolved)
        source = str(resolved)
    elif isinstance(prometheus, dict):
        samples = collect_prometheus_samples(
            prometheus,
            timeout_seconds=timeout_seconds,
            bearer_token=bearer_token,
            ca_file=ca_file,
        )
        source = str(prometheus.get("url", "prometheus"))
    else:
        raise ConfigurationError("SLO specification requires `data_file` or `prometheus`")
    findings, metrics = analyze_slo(name, objective, samples, _burn_windows(spec))
    partial = not samples or sum(item.total for item in samples) <= 0
    completed = utc_now()
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=name,
            partial=partial,
            capabilities=[
                "csv-json-sli-input",
                "prometheus-query-range",
                "error-budget-calculation",
                "multi-window-burn-rate",
                "no-data-detection",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={"source": source, "slo": metrics},
    )
