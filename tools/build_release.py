#!/usr/bin/env python3
"""Build a deterministic source archive from tracked-style repository content."""

from __future__ import annotations

import stat
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def _project_version() -> str:
    """Read the release version without requiring the package to be installed."""

    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle).get("project", {})
    version = project.get("version")
    if not isinstance(version, str) or not version.strip():
        raise RuntimeError("pyproject.toml does not define project.version")
    return version.strip()


EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "reports",
}
EXCLUDED_NAMES = {".coverage", "coverage.xml"}


def _release_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if path.name in EXCLUDED_NAMES or path.suffix == ".pyc":
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())


def main() -> int:
    version = _project_version()
    DIST.mkdir(exist_ok=True)
    archive = DIST / f"devops-automation-toolkit-{version}.zip"
    archive.unlink(missing_ok=True)
    prefix = f"devops-automation-toolkit-{version}"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in _release_files():
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(f"{prefix}/{relative}", date_time=(2026, 7, 21, 0, 0, 0))
            mode = path.stat().st_mode
            permissions = 0o755 if mode & stat.S_IXUSR else 0o644
            info.external_attr = permissions << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, path.read_bytes())
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
