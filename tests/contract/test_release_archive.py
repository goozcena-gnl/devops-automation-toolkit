from __future__ import annotations

import zipfile
from pathlib import Path

from tools import build_release


def test_source_archive_uses_canonical_git_modes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(build_release, "DIST", tmp_path)

    assert build_release.main() == 0

    archive = tmp_path / "devops-automation-toolkit-1.0.0.zip"
    prefix = "devops-automation-toolkit-1.0.0"
    with zipfile.ZipFile(archive) as bundle:
        assert _permissions(bundle, f"{prefix}/README.md") == 0o644
        assert _permissions(bundle, f"{prefix}/scripts/linux/linux-triage.sh") == 0o755
        assert _permissions(bundle, f"{prefix}/scripts/wrappers/devops-toolkit") == 0o755


def _permissions(bundle: zipfile.ZipFile, member: str) -> int:
    info = bundle.getinfo(member)
    assert info.create_system == 3
    return (info.external_attr >> 16) & 0o777
