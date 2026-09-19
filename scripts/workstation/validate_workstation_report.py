#!/usr/bin/env python3
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

root = Path(".")
report_schema = json.loads((root / "configs/schemas/report.schema.json").read_text())
finding_schema = json.loads((root / "configs/schemas/finding.schema.json").read_text())

resource = Resource.from_contents(finding_schema)
registry = (
    Registry()
    .with_resource("finding.schema.json", resource)
    .with_resource(finding_schema["$id"], resource)
)

report = json.loads((root / "workstation-report.json").read_text())
Draft202012Validator(report_schema, registry=registry).validate(report)
