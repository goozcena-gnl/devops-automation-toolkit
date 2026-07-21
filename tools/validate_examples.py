#!/usr/bin/env python3
"""Validate repository example files against their JSON schemas."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "configs" / "schemas"
EXAMPLES = ROOT / "configs" / "examples"


def load(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)


def main() -> int:
    toolkit_schema = load(SCHEMAS / "toolkit.schema.json")
    policy_schema = load(SCHEMAS / "policy.schema.json")
    Draft202012Validator(toolkit_schema, format_checker=FormatChecker()).validate(
        load(EXAMPLES / "toolkit.example.yaml")
    )
    for name in (
        "secret-policy.example.yaml",
        "iac-policy.example.yaml",
        "kubernetes-policy.example.yaml",
        "cloud-policy.example.yaml",
    ):
        Draft202012Validator(policy_schema, format_checker=FormatChecker()).validate(
            load(EXAMPLES / name)
        )
    print("Validated toolkit and policy examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
