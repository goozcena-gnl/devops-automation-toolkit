"""YAML/JSON configuration loading, merging, and validation."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from devops_toolkit.core.exceptions import ConfigurationError

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "defaults": {
        "format": "console",
        "severity_threshold": "high",
        "timeout_seconds": 30,
        "no_color": False,
    },
    "safety": {
        "production_patterns": [r"(?i)(^|[-_/])(prod|production|live)([-_/]|$)"],
        "production_allowlist": [],
        "require_production_acknowledgement": True,
    },
    "redaction": {"replacement": "[REDACTED]", "extra_patterns": []},
    "tools": {},
}


def _load_packaged_schema(name: str) -> dict[str, Any]:
    """Load a versioned JSON schema shipped inside the Python distribution."""

    resource = files("devops_toolkit.resources.schemas").joinpath(name)
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - packaging failure
        raise RuntimeError(f"Unable to load packaged schema {name}: {exc}") from exc
    if not isinstance(payload, dict):  # pragma: no cover - protected by contract tests
        raise RuntimeError(f"Packaged schema root must be an object: {name}")
    return payload


CONFIG_SCHEMA: dict[str, Any] = _load_packaged_schema("toolkit.schema.json")


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _read_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigurationError(f"Configuration file does not exist: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
        parsed = json.loads(raw) if path.suffix.lower() == ".json" else yaml.safe_load(raw)
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to parse configuration {path}: {exc}") from exc
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ConfigurationError(f"Configuration root must be a mapping: {path}")
    return parsed


def validate_config(config: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(CONFIG_SCHEMA).iter_errors(config), key=lambda item: list(item.path)
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ConfigurationError(f"Configuration validation failed: {details}")


def load_config(paths: list[Path] | None = None) -> dict[str, Any]:
    config = deepcopy(DEFAULT_CONFIG)
    for path in paths or []:
        config = deep_merge(config, _read_mapping(path))

    threshold = os.getenv("DEVOPS_TOOLKIT_SEVERITY_THRESHOLD")
    if threshold:
        config["defaults"]["severity_threshold"] = threshold
    timeout = os.getenv("DEVOPS_TOOLKIT_TIMEOUT_SECONDS")
    if timeout:
        try:
            config["defaults"]["timeout_seconds"] = int(timeout)
        except ValueError as exc:
            raise ConfigurationError("DEVOPS_TOOLKIT_TIMEOUT_SECONDS must be an integer") from exc
    validate_config(config)
    return config
