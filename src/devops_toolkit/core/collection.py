"""Stable coverage labels for report extensions."""

from enum import StrEnum


class CollectionState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    INTENTIONALLY_EXCLUDED = "intentionally_excluded"
    NOT_REQUESTED = "not_requested"
    NOT_APPLICABLE = "not_applicable"

    @property
    def incomplete(self) -> bool:
        return self in (CollectionState.PARTIAL, CollectionState.FAILED)
