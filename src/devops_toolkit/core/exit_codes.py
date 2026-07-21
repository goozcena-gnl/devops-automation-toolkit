"""Stable process exit-code contract."""

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    FINDINGS_EXCEEDED_THRESHOLD = 1
    INVALID_INPUT = 2
    DEPENDENCY_UNAVAILABLE = 3
    AUTHENTICATION_FAILURE = 4
    PARTIAL_COLLECTION = 5
    INTERNAL_ERROR = 6
    SAFETY_BLOCKED = 7
