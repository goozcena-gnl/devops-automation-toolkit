#!/usr/bin/env python3
"""Generate the Markdown tool catalog from the Python source of truth."""

from __future__ import annotations

from pathlib import Path

from devops_toolkit.catalog import TOOLS

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "generated-catalog.md"


def main() -> int:
    lines = [
        "# Generated tool catalog",
        "",
        "| Rank | Identifier | Name | Domain | Wave | Language |",
        "|---:|---|---|---|---:|---|",
    ]
    for tool in TOOLS:
        lines.append(
            f"| {tool.rank} | `{tool.identifier}` | {tool.display_name} | "
            f"{tool.domain} | {tool.phase} | {tool.language} |"
        )
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
