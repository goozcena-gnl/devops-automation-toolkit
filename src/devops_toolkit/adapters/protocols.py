"""Protocols for future HTTP and cloud adapters."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol


class PaginatedCollector(Protocol):
    def collect(self) -> Iterable[dict[str, Any]]: ...


class ReadOnlyHealthAdapter(Protocol):
    def health(self) -> dict[str, Any]: ...
