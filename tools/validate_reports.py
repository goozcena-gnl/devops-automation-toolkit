#!/usr/bin/env python3
"""Validate checked-in example reports against stable local contracts."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "configs" / "schemas"
REPORTS = ROOT / "examples" / "reports"


def main() -> int:
    report_schema = json.loads((SCHEMAS / "report.schema.json").read_text(encoding="utf-8"))
    finding_schema = json.loads((SCHEMAS / "finding.schema.json").read_text(encoding="utf-8"))
    finding_resource = Resource.from_contents(finding_schema)
    registry = (
        Registry()
        .with_resource("finding.schema.json", finding_resource)
        .with_resource(finding_schema["$id"], finding_resource)
    )
    validator = Draft202012Validator(
        report_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    report_count = 0
    sarif_count = 0
    for path in sorted(REPORTS.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".sarif"}:
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if path.suffix == ".sarif":
            if payload.get("version") != "2.1.0" or not isinstance(payload.get("runs"), list):
                raise ValueError(f"Invalid SARIF envelope: {path}")
            sarif_count += 1
        else:
            validator.validate(payload)
            report_count += 1
    print(f"Validated {report_count} toolkit reports and {sarif_count} SARIF reports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
