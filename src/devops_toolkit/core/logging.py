"""Structured logging with centralized redaction."""

from __future__ import annotations

import logging

from devops_toolkit.core.redaction import Redactor


class RedactingFilter(logging.Filter):
    def __init__(self, redactor: Redactor | None = None) -> None:
        super().__init__()
        self._redactor = redactor or Redactor()

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redactor.redact(str(record.msg))
        if record.args:
            record.args = tuple(self._redactor.redact(str(arg)) for arg in record.args)
        return True


def configure_logging(verbose: bool = False, redactor: Redactor | None = None) -> None:
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter(redactor))
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("devops_toolkit")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.propagate = False
