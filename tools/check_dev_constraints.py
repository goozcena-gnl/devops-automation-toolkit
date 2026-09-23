"""Generate or check the universal development constraints lock."""

from __future__ import annotations

import argparse
import difflib
import itertools
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "pyproject.toml"
CONSTRAINTS = ROOT / "requirements" / "dev-constraints.txt"
RESOLVE_TIMEOUT_SECONDS = 300
MAX_LOCK_BYTES = 1_000_000
MIN_PYTHON_VERSION = "3.11"


def normalized_lines(contents: str) -> list[str]:
    """Ignore only platform line endings and trailing blank lines."""
    return [line.rstrip() for line in contents.splitlines() if line.strip()]


def resolve(project: Path, resolver: Sequence[str] | None = None) -> str:
    """Resolve into a fresh temporary file, independent of committed pins."""
    command = list(resolver) if resolver is not None else [shutil.which("uv") or "uv"]
    with tempfile.TemporaryDirectory(prefix="dev-constraints-") as temp_dir:
        output = Path(temp_dir) / "expected.txt"
        args = [
            *command,
            "pip",
            "compile",
            "--universal",
            "--python-version",
            MIN_PYTHON_VERSION,
            "--extra",
            "dev",
            "--no-header",
            "--no-annotate",
            "--output-file",
            str(output),
            str(project),
        ]
        try:
            result = subprocess.run(  # noqa: S603
                args,
                cwd=project.parent,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=RESOLVE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("Dependency resolution could not complete") from exc
        if result.returncode != 0 or not output.is_file():
            raise RuntimeError(f"Dependency resolution failed (exit {result.returncode})")
        if output.stat().st_size > MAX_LOCK_BYTES:
            raise RuntimeError("Dependency resolution exceeded the output limit")
        return output.read_text(encoding="utf-8")


def run(
    operation: str,
    *,
    project: Path = PROJECT,
    constraints: Path = CONSTRAINTS,
    resolver: Sequence[str] | None = None,
) -> int:
    expected = resolve(project, resolver)
    if operation == "generate":
        constraints.parent.mkdir(parents=True, exist_ok=True)
        constraints.write_text(
            "\n".join(normalized_lines(expected)) + "\n", encoding="utf-8", newline="\n"
        )
        print(f"Generated {constraints}")
        return 0
    if operation != "check":
        raise ValueError(f"Unknown operation: {operation}")
    if not constraints.is_file():
        print(f"Missing constraints: {constraints}", file=sys.stderr)
        return 1
    actual_lines = normalized_lines(constraints.read_text(encoding="utf-8"))
    expected_lines = normalized_lines(expected)
    if actual_lines == expected_lines:
        print("Development constraints match the resolved dependency graph")
        return 0
    print("Development constraints drifted; run the generate operation", file=sys.stderr)
    diff = difflib.unified_diff(
        actual_lines,
        expected_lines,
        fromfile=str(constraints),
        tofile="fresh resolution",
        lineterm="",
    )
    for line in itertools.islice(diff, 40):
        print(line, file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("generate", "check"))
    args = parser.parse_args()
    try:
        return run(args.operation)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
