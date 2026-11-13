#!/usr/bin/env python3
"""Validate a release tag against the exact canonical package version."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence

_VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:rc(0|[1-9][0-9]*))?",
    re.ASCII,
)


def expected_release_tag(package_version: str) -> str:
    """Map canonical PEP 440 stable/RC versions to the project's tag convention."""
    match = _VERSION.fullmatch(package_version)
    if match is None:
        raise ValueError("unsupported package version; expected X.Y.Z or X.Y.ZrcN")
    major, minor, patch, rc_number = match.groups()
    suffix = f"-rc.{rc_number}" if rc_number is not None else ""
    return f"v{major}.{minor}.{patch}{suffix}"


def verify_release_tag(package_version: str, actual_tag: str) -> None:
    """Reject noncanonical tags rather than silently normalizing user input."""
    expected = expected_release_tag(package_version)
    if actual_tag != expected:
        raise ValueError(f"release tag mismatch: expected {expected!r}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, dest="package_version")
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        verify_release_tag(args.package_version, args.tag)
    except ValueError as error:
        print(f"Release tag verification failed: {error}", file=sys.stderr)
        return 1
    print("Release tag matches package version")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
