"""Exercise deterministic lock validation with uv and an offline wheel index."""

from __future__ import annotations

import json
import runpy
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile

import pytest

pytestmark = pytest.mark.integration
run = runpy.run_path(
    str(Path(__file__).resolve().parents[2] / "tools" / "check_dev_constraints.py")
)["run"]


def publish_wheel(directory: Path, name: str, version: str, *dependencies: str) -> None:
    """Publish just the metadata uv needs; no build tools or network are involved."""
    stem = f"{name}-{version}"
    metadata = (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nRequires-Python: >=3.11\n"
        + "".join(f"Requires-Dist: {dependency}\n" for dependency in dependencies)
    )
    with ZipFile(directory / f"{stem}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(f"{stem}.dist-info/METADATA", metadata)
        wheel.writestr(
            f"{stem}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        wheel.writestr(f"{stem}.dist-info/RECORD", "")


@dataclass
class LockedProject:
    workspace: Path
    project: Path
    constraints: Path
    wheelhouse: Path

    def write_manifest(
        self, dependencies: tuple[str, ...] = ("alpha>=1,<2",), *, added_dev: bool = False
    ) -> None:
        dev = ["gamma==1.0", *(["delta==1.0"] if added_dev else [])]
        self.project.write_text(
            "[project]\nname = 'lock-fixture'\nversion = '1.0'\nrequires-python = '>=3.11'\n"
            f"dependencies = {json.dumps(dependencies)}\n"
            f"[project.optional-dependencies]\ndev = {json.dumps(dev)}\n",
            encoding="utf-8",
        )

    def resolve(self, operation: str) -> int:
        return run(
            operation,
            project=self.project,
            constraints=self.constraints,
            resolver=[sys.executable, "-m", "uv", "--offline", "--no-config", "--no-cache"],
        )

    def check_without_changes(self) -> int:
        def snapshot() -> dict[Path, bytes]:
            return {
                path.relative_to(self.workspace): path.read_bytes()
                for path in self.workspace.rglob("*")
                if path.is_file()
            }

        before = snapshot()
        try:
            return self.resolve("check")
        finally:
            assert snapshot() == before


@pytest.fixture
def locked_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> LockedProject:
    workspace = tmp_path / "project with spaces"
    workspace.mkdir()
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    monkeypatch.setenv("UV_FIND_LINKS", wheelhouse.as_uri())
    monkeypatch.setenv("UV_NO_INDEX", "true")
    publish_wheel(wheelhouse, "alpha", "1.0", "beta>=1,<2")
    publish_wheel(wheelhouse, "alpha", "2.0", "beta>=2,<3")
    publish_wheel(wheelhouse, "beta", "1.0")
    publish_wheel(wheelhouse, "beta", "2.0")
    publish_wheel(wheelhouse, "gamma", "1.0")
    publish_wheel(wheelhouse, "delta", "1.0")
    fixture = LockedProject(
        workspace,
        workspace / "pyproject.toml",
        workspace / "requirements" / "dev-constraints.txt",
        wheelhouse,
    )
    fixture.write_manifest()
    assert fixture.resolve("generate") == 0
    assert fixture.constraints.read_text(encoding="utf-8") == (
        "alpha==1.0\nbeta==1.0\ngamma==1.0\n"
    )
    return fixture


def test_check_keeps_valid_transitive_pin_after_new_release(locked_project: LockedProject) -> None:
    assert locked_project.check_without_changes() == 0

    publish_wheel(locked_project.wheelhouse, "beta", "1.1")

    assert locked_project.check_without_changes() == 0
    assert "beta==1.0\n" in locked_project.constraints.read_text(encoding="utf-8")


def test_generate_refreshes_to_new_compatible_release(locked_project: LockedProject) -> None:
    publish_wheel(locked_project.wheelhouse, "beta", "1.1")
    manifest_before = locked_project.project.read_bytes()

    assert locked_project.resolve("generate") == 0

    assert locked_project.constraints.read_text(encoding="utf-8") == (
        "alpha==1.0\nbeta==1.1\ngamma==1.0\n"
    )
    assert locked_project.project.read_bytes() == manifest_before
    assert locked_project.check_without_changes() == 0


def test_check_detects_added_direct_dev_dependency(locked_project: LockedProject) -> None:
    locked_project.write_manifest(added_dev=True)

    assert locked_project.check_without_changes() == 1


def test_check_detects_removed_direct_dependency(locked_project: LockedProject) -> None:
    locked_project.write_manifest(dependencies=())

    assert locked_project.check_without_changes() == 1


def test_check_rejects_incompatible_direct_dependency_change(locked_project: LockedProject) -> None:
    locked_project.write_manifest(dependencies=("alpha>=2,<3",))

    with pytest.raises(RuntimeError, match="Dependency resolution failed"):
        locked_project.check_without_changes()


def test_check_detects_missing_required_transitive(locked_project: LockedProject) -> None:
    locked_project.constraints.write_text("alpha==1.0\ngamma==1.0\n", encoding="utf-8")

    assert locked_project.check_without_changes() == 1


def test_check_rejects_incompatible_committed_pin(locked_project: LockedProject) -> None:
    locked_project.constraints.write_text("alpha==2.0\nbeta==1.0\ngamma==1.0\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Dependency resolution failed"):
        locked_project.check_without_changes()
