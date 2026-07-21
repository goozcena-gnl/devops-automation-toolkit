from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def test_phase5_example_reports_match_schema(repository_root: Path) -> None:
    schema_dir = repository_root / "configs/schemas"
    report_schema = json.loads((schema_dir / "report.schema.json").read_text())
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text())
    resource = Resource.from_contents(finding_schema)
    registry = (
        Registry()
        .with_resource("finding.schema.json", resource)
        .with_resource(finding_schema["$id"], resource)
    )
    validator = Draft202012Validator(report_schema, registry=registry)
    paths = sorted((repository_root / "examples/reports/phase5").glob("*.json"))
    assert len(paths) == 5
    for path in paths:
        validator.validate(json.loads(path.read_text()))
