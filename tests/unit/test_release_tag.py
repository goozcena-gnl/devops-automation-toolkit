"""Exercise both stable and prerelease tag validation used by release.yml."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

checker = runpy.run_path(str(Path(__file__).resolve().parents[2] / "tools/check_release_tag.py"))
expected_release_tag = checker["expected_release_tag"]
verify_release_tag = checker["verify_release_tag"]
run = checker["main"]


@pytest.mark.parametrize(
    ("package_version", "tag"),
    [
        ("1.0.2", "v1.0.2"),
        ("2.0.0rc1", "v2.0.0-rc.1"),
        ("2.0.0rc2", "v2.0.0-rc.2"),
        ("2.0.0", "v2.0.0"),
        ("0.9.0", "v0.9.0"),
    ],
)
def test_canonical_release_tags(package_version: str, tag: str) -> None:
    assert expected_release_tag(package_version) == tag
    verify_release_tag(package_version, tag)
    assert run(["--version", package_version, "--tag", tag]) == 0


@pytest.mark.parametrize(
    ("package_version", "bad_tag"),
    [
        ("2.0.0rc1", "v2.0.0"),
        ("2.0.0rc1", "v2.0.0rc1"),
        ("2.0.0rc1", "v2.0.0-rc.2"),
        ("2.0.0", "v2.0.0-rc.1"),
        ("1.0.2", "v1.0.3"),
        ("1.0.2", "1.0.2"),
        ("2.0.0rc1", "V2.0.0-rc.1"),
        ("2.0.0rc1", "v2.0.0-rc.01"),
    ],
)
def test_mismatched_tags_fail_closed(package_version: str, bad_tag: str) -> None:
    with pytest.raises(ValueError, match="release tag mismatch"):
        verify_release_tag(package_version, bad_tag)
    assert run(["--version", package_version, "--tag", bad_tag]) == 1


@pytest.mark.parametrize(
    "invalid_version",
    [
        "", "2.0", "v2.0.0", "2.0.0-rc.1", "2.0.0rc", "2.0.0rc01",
        "02.0.0", "2.00.0", "2.0.0a1", "2.0.0.dev1", "2.0.0.post1",
        "2.0.0+local", "2.0.0\n",
    ],
)
def test_unsupported_versions_fail_closed(invalid_version: str) -> None:
    with pytest.raises(ValueError, match="unsupported package version"):
        expected_release_tag(invalid_version)
    assert run(["--version", invalid_version, "--tag", "v2.0.0"]) == 1


def test_release_workflow_uses_shared_checker() -> None:
    workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    assert "python tools/check_release_tag.py" in workflow
    assert '--version "$(devops-toolkit version)"' in workflow
    assert '--tag "$GITHUB_REF_NAME"' in workflow
