from __future__ import annotations

from enum import Enum


class StreamReferenceType(Enum):
    """How a stream of a directory entry refers to a resource."""

    DEFAULT_STREAM = "default_stream"
    ALTERNATE_STREAM = "alternate_stream"
    EMPTY_STREAM = "empty_stream"
    MISSING_RESOURCE = "missing_resource"

    @property
    def is_named_stream(self) -> bool:
        """Whether the reference is an explicitly named alternate data stream."""
        return self is StreamReferenceType.ALTERNATE_STREAM

    @property
    def has_resource(self) -> bool:
        """Whether references of this kind resolve to a resource in the resource table."""
        return self in (
            StreamReferenceType.DEFAULT_STREAM,
            StreamReferenceType.ALTERNATE_STREAM,
        )
