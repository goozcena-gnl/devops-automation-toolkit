"""Safe model serialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from devops_toolkit.core.filesystem import atomic_write_text
from devops_toolkit.core.models import Report


def report_to_json(report: Report, *, indent: int = 2) -> str:
    return json.dumps(report.as_dict(), indent=indent, sort_keys=False) + "\n"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2) + "\n")
