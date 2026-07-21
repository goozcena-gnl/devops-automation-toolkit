#!/usr/bin/env python3
"""Validate local Markdown links and required release documentation."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
REQUIRED_FILES = {
    Path("README.md"),
    Path("SECURITY.md"),
    Path("CONTRIBUTING.md"),
    Path("CHANGELOG.md"),
    Path("AGENTS.md"),
    Path("docs/architecture.md"),
    Path("docs/compatibility.md"),
    Path("docs/release-process.md"),
    Path("docs/script-catalog.md"),
    Path("docs/validation-matrix.md"),
}


def _target_path(source: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
    if not target or target.startswith(("#", "http://", "https://", "mailto:")):
        return None
    target = unquote(target.split("#", 1)[0])
    if not target:
        return None
    if target.startswith("/"):
        return ROOT / target.lstrip("/")
    return source.parent / target


def main() -> int:
    errors: list[str] = []
    for required in sorted(REQUIRED_FILES):
        if not (ROOT / required).is_file():
            errors.append(f"Missing required documentation: {required}")

    for source in sorted(ROOT.rglob("*.md")):
        if any(
            part in {".venv", "build", "dist"} or part.endswith(".egg-info")
            for part in source.parts
        ):
            continue
        text = source.read_text(encoding="utf-8")
        for raw_target in LINK_RE.findall(text):
            target = _target_path(source, raw_target)
            if target is not None and not target.exists():
                errors.append(f"Broken local link in {source.relative_to(ROOT)}: {raw_target}")

    if errors:
        print("\n".join(errors))
        return 1
    print("Documentation links and required files are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
