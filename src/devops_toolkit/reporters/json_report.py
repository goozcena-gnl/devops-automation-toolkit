"""JSON reporter."""

from devops_toolkit.core.models import Report
from devops_toolkit.core.serialization import report_to_json


def render_json(report: Report) -> str:
    return report_to_json(report)
