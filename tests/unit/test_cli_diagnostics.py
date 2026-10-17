"""CLI entry points and diagnostics must remain safe with untrusted arguments."""

import re

import pytest
from typer.testing import CliRunner

from devops_toolkit.catalog import TOOLS
from devops_toolkit.cli import app

runner = CliRunner()


@pytest.mark.parametrize(
    "command", [tool.identifier for tool in TOOLS if tool.language == "Python"]
)
def test_python_tool_help(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])

    assert result.exit_code == 0
    assert command in result.stdout
    assert "--help" in result.stdout
    assert "--format" in result.stdout


@pytest.mark.parametrize("prefix", ["", "--"], ids=["extra-argument", "unknown-option"])
@pytest.mark.parametrize(
    ("value", "escaped"),
    [
        ("\x1b[2J", r"\x1b[2J"),
        ("\x1b]52;c;YWJj\x07", r"\x1b]52;c;YWJj\x07"),
        ("\x9b2J", r"\x9b2J"),
        ("\r\n\t\b\x7f", r"\x0d\x0a\x09\x08\x7f"),
    ],
    ids=["screen-control", "clipboard-control", "c1-control", "whitespace-controls"],
)
def test_invalid_argument_escapes_terminal_controls(
    prefix: str, value: str, escaped: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer import rich_utils

    monkeypatch.setattr(rich_utils, "MAX_WIDTH", 300)
    result = runner.invoke(app, ["version", prefix + "input-" + value], color=False)

    assert result.exit_code == 2
    # Strip only generated color styles; other terminal controls must stay visible to this test.
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stderr)
    assert prefix + "input-" + escaped in output
    assert re.search(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]", output) is None
