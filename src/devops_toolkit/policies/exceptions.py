"""Expiring finding exceptions."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from devops_toolkit.core.models import Finding


class PolicyException(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    justification: str = Field(min_length=5)
    expires_at: datetime

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return expires > current


def apply_exceptions(
    findings: list[Finding],
    exceptions: list[PolicyException],
    *,
    now: datetime | None = None,
) -> list[Finding]:
    active = {item.fingerprint: item for item in exceptions if item.is_active(now)}
    result: list[Finding] = []
    for finding in findings:
        updated = finding.model_copy(deep=True)
        exception = active.get(updated.fingerprint)
        if exception:
            updated.suppressed = True
            updated.suppression_reason = exception.justification
        result.append(updated)
    return result
