from pathlib import Path

from devops_toolkit.core.filesystem import atomic_write_text, private_temporary_directory


def test_atomic_write_text(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "report.txt"
    atomic_write_text(output, "hello\n")
    assert output.read_text(encoding="utf-8") == "hello\n"


def test_private_temporary_directory_is_removed() -> None:
    captured: Path | None = None
    with private_temporary_directory() as directory:
        captured = directory
        assert directory.exists()
    assert captured is not None
    assert not captured.exists()
