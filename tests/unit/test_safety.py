import pytest

from devops_toolkit.core.exceptions import SafetyBlockedError
from devops_toolkit.core.safety import (
    SafetyPolicy,
    TargetRisk,
    classify_target,
    evaluate_target,
    require_safe_target,
)


def test_production_like_target_is_detected() -> None:
    policy = SafetyPolicy()
    assert classify_target("aks-prod-west-europe", policy) is TargetRisk.PRODUCTION_LIKE


def test_non_production_target_is_allowed() -> None:
    decision = evaluate_target("homelab-dev", SafetyPolicy())
    assert decision.allowed is True
    assert decision.risk is TargetRisk.NON_PRODUCTION


def test_production_requires_acknowledgement() -> None:
    with pytest.raises(SafetyBlockedError):
        require_safe_target("production-cluster", SafetyPolicy())


def test_acknowledged_production_is_allowed() -> None:
    decision = require_safe_target(
        "production-cluster",
        SafetyPolicy(),
        production_acknowledged=True,
    )
    assert decision.allowed is True
