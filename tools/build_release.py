#!/usr/bin/env python3
"""Build a deterministic source archive from tracked-style repository content."""

from __future__ import annotations

import subprocess
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


def _release_entries() -> list[tuple[Path, int]]:
    """Return tracked files and their canonical Git modes."""

    result = subprocess.run(
        ["git", "ls-files", "--stage", "-z"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    entries: list[tuple[Path, int]] = []
    records = result.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    for record in records:
        if not record:
            continue
        metadata, relative_text = record.split("\t", maxsplit=1)
        mode_text, _object_id, stage = metadata.split()
        if stage != "0":
            continue
        relative = Path(relative_text)
        if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.name in EXCLUDED_NAMES or relative.suffix == ".pyc":
            continue
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"Tracked release file is unavailable: {relative.as_posix()}")
        entries.append((path, int(mode_text, 8)))
    return sorted(entries, key=lambda item: item[0].relative_to(ROOT).as_posix())


def main() -> int:
    version = _project_version()
    DIST.mkdir(exist_ok=True)
    archive = DIST / f"devops-automation-toolkit-{version}.zip"
    archive.unlink(missing_ok=True)
    prefix = f"devops-automation-toolkit-{version}"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path, git_mode in _release_entries():
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(f"{prefix}/{relative}", date_time=(2026, 7, 21, 0, 0, 0))
            permissions = 0o755 if git_mode & 0o111 else 0o644
            info.create_system = 3
            info.external_attr = (0o100000 | permissions) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, path.read_bytes())
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
