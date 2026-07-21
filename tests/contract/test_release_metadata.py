from __future__ import annotations

import json
import tomllib
from importlib.resources import files
from pathlib import Path

from devops_toolkit.catalog import TOOLS
from devops_toolkit.core.config import CONFIG_SCHEMA
from devops_toolkit.version import __version__


def test_version_metadata_is_consistent(repository_root: Path) -> None:
    pyproject = tomllib.loads((repository_root / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__
    assert f'tool_version = "{__version__}"' in (
        repository_root / "scripts/workstation/devops-workstation-audit.ps1"
    ).read_text(encoding="utf-8")
    assert f'"tool_version": "{__version__}"' in (
        repository_root / "scripts/linux/linux-triage.sh"
    ).read_text(encoding="utf-8")


def test_catalog_contains_twenty_unique_implemented_tools(repository_root: Path) -> None:
    assert len(TOOLS) == 20
    assert len({tool.identifier for tool in TOOLS}) == 20
    for tool in TOOLS:
        doc = repository_root / "docs" / "tools" / f"{tool.identifier}.md"
        assert doc.is_file(), f"Missing documentation for {tool.identifier}"


def test_catalog_tools_have_checked_in_examples(repository_root: Path) -> None:
    example_tools: set[str] = set()
    for path in (repository_root / "examples/reports").rglob("*"):
        if not path.is_file() or path.suffix not in {".json", ".sarif"}:
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if path.suffix == ".sarif":
            for run in payload.get("runs", []):
                name = run.get("tool", {}).get("driver", {}).get("name")
                if isinstance(name, str):
                    example_tools.add(name)
        else:
            name = payload.get("metadata", {}).get("tool")
            if isinstance(name, str):
                example_tools.add(name)
    assert {tool.identifier for tool in TOOLS} <= example_tools


def test_packaged_schemas_match_repository_contracts(repository_root: Path) -> None:
    repository_schemas = repository_root / "configs" / "schemas"
    packaged_schemas = files("devops_toolkit.resources.schemas")
    for name in (
        "toolkit.schema.json",
        "finding.schema.json",
        "policy.schema.json",
        "report.schema.json",
    ):
        repository_payload = json.loads((repository_schemas / name).read_text(encoding="utf-8"))
        packaged_payload = json.loads(packaged_schemas.joinpath(name).read_text(encoding="utf-8"))
        assert packaged_payload == repository_payload
    assert (
        json.loads((repository_schemas / "toolkit.schema.json").read_text(encoding="utf-8"))
        == CONFIG_SCHEMA
    )


def test_release_files_do_not_contain_owner_placeholders(repository_root: Path) -> None:
    codeowners = (repository_root / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert "@repository-owner" not in codeowners
    assert "@goozcena-gnl" in codeowners


def test_examples_do_not_expose_build_environment_paths(repository_root: Path) -> None:
    forbidden = ("/mnt/data/", "/home/", "C:\\Users\\", "\\\\wsl$\\", " oai ")
    for path in (repository_root / "examples/reports").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert all(marker not in text for marker in forbidden), path


def test_packaged_report_schema_validates_without_network_resolution(repository_root: Path) -> None:
    """The distributed report contract must work offline without a custom registry."""

    from jsonschema import Draft202012Validator

    schema_root = files("devops_toolkit.resources.schemas")
    report_schema = json.loads(schema_root.joinpath("report.schema.json").read_text())
    example = json.loads(
        (repository_root / "examples/reports/sample-report.json").read_text(encoding="utf-8")
    )

    Draft202012Validator(report_schema).validate(example)
