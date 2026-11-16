from __future__ import annotations


class Error(Exception):
    pass


class InvalidHeaderError(Error):
    pass


class InvalidDatumError(InvalidHeaderError):
    """Raised when a BitLocker datum cannot be safely framed inside its parent.

    Args:
        message: Human readable description of the framing problem.
        offset: Offset of the offending datum, relative to the buffer it was parsed from.
        reason: Stable machine readable reason, one of ``truncated_header``, ``zero_size``,
            ``undersized``, ``out_of_bounds``, ``truncated``, ``truncated_struct``,
            ``invalid_bounds``, ``empty``, ``trailing_data`` or ``too_deep``.
        depth: Nesting depth at which the problem was found, if applicable.
    """

    def __init__(
        self,
        message: str,
        *,
        offset: int | None = None,
        reason: str | None = None,
        depth: int | None = None,
    ) -> None:
        super().__init__(message)
        self.offset = offset
        self.reason = reason
        self.depth = depth
