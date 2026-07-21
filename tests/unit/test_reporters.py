import json

from devops_toolkit.reporters.console import render_console
from devops_toolkit.reporters.json_report import render_json
from devops_toolkit.reporters.markdown import render_markdown
from devops_toolkit.reporters.sarif import render_sarif
from devops_toolkit.sample import build_sample_report


def test_json_report_is_parseable() -> None:
    payload = json.loads(render_json(build_sample_report()))
    assert payload["schema_version"] == "1.0"
    assert payload["findings"][0]["id"] == "FOUNDATION-EXAMPLE"


def test_markdown_contains_summary_and_finding() -> None:
    output = render_markdown(build_sample_report())
    assert "## Summary" in output
    assert "Synthetic foundation finding" in output


def test_sarif_is_parseable() -> None:
    payload = json.loads(render_sarif(build_sample_report()))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "FOUNDATION-EXAMPLE"


def test_console_renders_without_color() -> None:
    output = render_console(build_sample_report(), color=False)
    assert "devops-toolkit" in output
    assert "Synthetic foundation finding" in output
