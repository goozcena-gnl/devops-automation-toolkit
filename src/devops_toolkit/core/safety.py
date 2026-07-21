"""Production-target classification and execution blocking."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from devops_toolkit.core.exceptions import SafetyBlockedError


class TargetRisk(StrEnum):
    NON_PRODUCTION = "non-production"
    UNKNOWN = "unknown"
    PRODUCTION_LIKE = "production-like"


DEFAULT_PRODUCTION_PATTERNS = [r"(?i)(^|[-_/])(prod|production|live)([-_/]|$)"]


@dataclass(frozen=True)
class SafetyPolicy:
    production_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_PRODUCTION_PATTERNS)
    )
    production_allowlist: list[str] = field(default_factory=list)
    require_production_acknowledgement: bool = True


@dataclass(frozen=True)
class SafetyDecision:
    target: str
    risk: TargetRisk
    allowed: bool
    reason: str


def classify_target(target: str, policy: SafetyPolicy) -> TargetRisk:
    normalized = target.strip()
    if not normalized:
        return TargetRisk.UNKNOWN
    if normalized in policy.production_allowlist:
        return TargetRisk.PRODUCTION_LIKE
    if any(re.search(pattern, normalized) for pattern in policy.production_patterns):
        return TargetRisk.PRODUCTION_LIKE
    return TargetRisk.NON_PRODUCTION


def evaluate_target(
    target: str,
    policy: SafetyPolicy,
    *,
    production_acknowledged: bool = False,
) -> SafetyDecision:
    risk = classify_target(target, policy)
    if (
        risk is TargetRisk.PRODUCTION_LIKE
        and policy.require_production_acknowledgement
        and not production_acknowledged
    ):
        return SafetyDecision(
            target=target,
            risk=risk,
            allowed=False,
            reason="Production-like target requires explicit acknowledgement",
        )
    return SafetyDecision(target=target, risk=risk, allowed=True, reason="Safety policy satisfied")


def require_safe_target(
    target: str,
    policy: SafetyPolicy,
    *,
    production_acknowledged: bool = False,
) -> SafetyDecision:
    decision = evaluate_target(
        target,
        policy,
        production_acknowledged=production_acknowledged,
    )
    if not decision.allowed:
        raise SafetyBlockedError(decision.reason)
    return decision
