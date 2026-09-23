"""Regression tests for the real constraints comparison path."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

EXPECTED = "alpha==1.0\nbeta==2.0 ; sys_platform == 'win32'\n"
run = runpy.run_path(
    str(Path(__file__).resolve().parents[2] / "tools" / "check_dev_constraints.py")
)["run"]


def fake_resolver(tmp_path: Path) -> list[str]:
    """A local compiler process keeps these tests independent of PyPI."""
    script = tmp_path / "fake resolver.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "assert '--universal' in sys.argv\n"
        "assert sys.argv[sys.argv.index('--python-version') + 1] == '3.11'\n"
        "output = Path(sys.argv[sys.argv.index('--output-file') + 1])\n"
        f"output.write_text({EXPECTED!r}, encoding='utf-8')\n",
        encoding="utf-8",
    )
    return [sys.executable, str(script)]


@pytest.mark.parametrize(
    ("committed", "expected_status"),
    [
        (EXPECTED, 0),
        ("alpha==1.1\nbeta==2.0 ; sys_platform == 'win32'\n", 1),
        (EXPECTED + "gamma==3.0\n", 1),
        ("alpha==1.0\n", 1),
    ],
    ids=("clean", "version-changed", "dependency-added", "dependency-removed"),
)
def test_check_compares_fresh_resolution_without_side_effects(
    tmp_path: Path, committed: str, expected_status: int
) -> None:
    workspace = tmp_path / "Windows path with spaces"
    workspace.mkdir()
    project = workspace / "pyproject.toml"
    project.write_text("[project]\nname = 'fixture'\nversion = '1.0'\n", encoding="utf-8")
    constraints = workspace / "requirements" / "dev-constraints.txt"
    constraints.parent.mkdir()
    constraints.write_text(committed, encoding="utf-8")
    resolver = fake_resolver(workspace)
    before = {
        path.relative_to(workspace): path.read_bytes()
        for path in workspace.rglob("*")
        if path.is_file()
    }

    status = run("check", project=project, constraints=constraints, resolver=resolver)

    after = {
        path.relative_to(workspace): path.read_bytes()
        for path in workspace.rglob("*")
        if path.is_file()
    }
    assert status == expected_status
    assert after == before


def test_generate_uses_same_resolver_and_writes_lock(tmp_path: Path) -> None:
    project = tmp_path / "pyproject.toml"
    project.write_text("[project]\nname = 'fixture'\nversion = '1.0'\n", encoding="utf-8")
    constraints = tmp_path / "requirements" / "dev-constraints.txt"

    status = run(
        "generate", project=project, constraints=constraints, resolver=fake_resolver(tmp_path)
    )

    assert status == 0
    assert constraints.read_text(encoding="utf-8") == EXPECTED
