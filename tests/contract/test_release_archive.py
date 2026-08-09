from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path
from types import ModuleType


def test_source_archive_uses_canonical_git_modes(
    repository_root: Path, tmp_path: Path, monkeypatch
) -> None:
    build_release = _load_build_release(repository_root)
    monkeypatch.setattr(build_release, "DIST", tmp_path)

    assert build_release.main() == 0

    archive = tmp_path / "devops-automation-toolkit-1.0.1.zip"
    prefix = "devops-automation-toolkit-1.0.1"
    with zipfile.ZipFile(archive) as bundle:
        assert _permissions(bundle, f"{prefix}/README.md") == 0o644
        assert _permissions(bundle, f"{prefix}/scripts/linux/linux-triage.sh") == 0o755
        assert _permissions(bundle, f"{prefix}/scripts/wrappers/devops-toolkit") == 0o755


def _permissions(bundle: zipfile.ZipFile, member: str) -> int:
    info = bundle.getinfo(member)
    assert info.create_system == 3
    return (info.external_attr >> 16) & 0o777


def _load_build_release(repository_root: Path) -> ModuleType:
    script = repository_root / "tools" / "build_release.py"
    spec = importlib.util.spec_from_file_location("release_builder_under_test", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load release builder: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
