"""SARIF 2.1.0 reporter for code-scanning integration."""

from __future__ import annotations

import json
from typing import Any

from devops_toolkit.core.models import Finding, Report, Severity

SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def _result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": SARIF_LEVEL[finding.severity],
        "message": {"text": finding.title},
        "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
        "properties": {
            "category": finding.category,
            "confidence": finding.confidence.value,
            "suppressed": finding.suppressed,
            "recommendation": finding.recommendation,
        },
    }
    if finding.evidence.location:
        region: dict[str, int] = {}
        if finding.evidence.line:
            region["startLine"] = finding.evidence.line
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.evidence.location},
                    "region": region,
                }
            }
        ]
    return result


def render_sarif(report: Report) -> str:
    rules: dict[str, dict[str, Any]] = {}
    for finding in report.findings:
        rules.setdefault(
            finding.id,
            {
                "id": finding.id,
                "name": finding.id.replace("-", "_").lower(),
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.recommendation or finding.description or finding.title},
                "properties": {"category": finding.category},
            },
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.metadata.tool,
                        "version": report.metadata.tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(finding) for finding in report.findings],
            }
        ],
    }
    return json.dumps(payload, indent=2) + "\n"
