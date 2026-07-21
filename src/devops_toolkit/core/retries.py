"""Bounded retry helpers for safe read operations."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def retry_call(
    operation: Callable[[], T],
    *,
    attempts: int = 3,
    initial_delay_seconds: float = 0.25,
    maximum_delay_seconds: float = 4.0,
    retry_on: tuple[type[Exception], ...] = (OSError, TimeoutError),
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    if attempts < 1:
        raise ValueError("attempts must be at least one")
    delay = initial_delay_seconds
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except retry_on:
            if attempt == attempts:
                raise
            sleep(min(delay, maximum_delay_seconds))
            delay = min(delay * 2, maximum_delay_seconds)
    raise RuntimeError("unreachable retry state")
