"""Normalized report and finding models."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ReportStatus(StrEnum):
    PASS = "pass"  # nosec B105
    WARNING = "warning"
    FAIL = "fail"
    ERROR = "error"
    BLOCKED = "blocked"


class ResourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    name: str
    namespace: str | None = None
    provider: str | None = None
    identifier: str | None = None


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    location: str | None = None
    line: int | None = Field(default=None, ge=1)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=3)
    tool: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: Severity
    confidence: Confidence
    title: str = Field(min_length=1)
    description: str = ""
    recommendation: str = ""
    fingerprint: str = ""
    resource: ResourceRef | None = None
    evidence: Evidence = Field(default_factory=lambda: Evidence(summary="No evidence supplied"))
    references: list[str] = Field(default_factory=list)
    suppressed: bool = False
    suppression_reason: str | None = None

    @model_validator(mode="after")
    def ensure_fingerprint(self) -> Finding:
        if not self.fingerprint:
            stable_parts = [
                self.id,
                self.tool,
                self.category,
                self.title,
                self.resource.type if self.resource else "",
                self.resource.name if self.resource else "",
                self.resource.namespace or "" if self.resource else "",
            ]
            digest = sha256("\x1f".join(stable_parts).encode("utf-8")).hexdigest()
            self.fingerprint = f"sha256:{digest}"
        return self


class ReportMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    tool_version: str
    started_at: datetime
    completed_at: datetime
    target: str
    partial: bool = False
    capabilities: list[str] = Field(default_factory=list)


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    metadata: ReportMetadata
    findings: list[Finding] = Field(default_factory=list)
    status: ReportStatus = ReportStatus.PASS
    summary: dict[str, int] = Field(default_factory=dict)
    extensions: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def calculate_summary(self) -> Report:
        counts = Counter(f.severity.value for f in self.findings if not f.suppressed)
        self.summary = {severity.value: counts.get(severity.value, 0) for severity in Severity}
        self.summary["suppressed"] = sum(1 for finding in self.findings if finding.suppressed)
        self.summary["total"] = len(self.findings)
        return self

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


def utc_now() -> datetime:
    return datetime.now(UTC)
