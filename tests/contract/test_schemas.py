import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from devops_toolkit.sample import build_sample_report


def test_sample_report_matches_repository_schema(repository_root: Path) -> None:
    schema_dir = repository_root / "configs/schemas"
    report_schema = json.loads((schema_dir / "report.schema.json").read_text(encoding="utf-8"))
    finding_schema = json.loads((schema_dir / "finding.schema.json").read_text(encoding="utf-8"))
    resource = Resource.from_contents(finding_schema)
    registry = (
        Registry()
        .with_resource("finding.schema.json", resource)
        .with_resource(finding_schema["$id"], resource)
    )
    Draft202012Validator(report_schema, registry=registry).validate(build_sample_report().as_dict())
