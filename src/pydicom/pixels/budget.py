# Copyright 2008-2024 pydicom authors. See LICENSE file for details.
"""Optional resource budget for a single pixel data decode operation."""

from __future__ import annotations

from dataclasses import dataclass


class DecodeBudgetExceeded(Exception):
    """Raised when a pixel data decode operation exceeds its budget.

    .. versionadded:: 3.1

    The exception is intentionally distinct from the ordinary decoding errors
    (such as :class:`RuntimeError` when all available plugins fail) so that a
    caller can tell a deliberately limited decode apart from malformed data.

    Attributes
    ----------
    budget : DecodeBudget
        The budget that was exceeded. Its counters reflect the work that had
        been completed when the limit was reached.
    frames_decoded : int
        The number of frames that had been fully decoded and delivered before
        the limit was reached.
    bytes_allocated : int
        The number of bytes that had been counted against the budget before
        the limit was reached.
    requested_frames : int
        The number of additional frames the decode wanted to account for.
    requested_bytes : int
        The number of additional bytes the decode wanted to account for.
    result_usable : bool
        Whether the result already produced can still be used. This is
        ``True`` for per-frame iteration, where the previously yielded frames
        are complete, and ``False`` for whole-array decoding, where the
        partially assembled array must not be used.
    """

    def __init__(
        self,
        message: str,
        *,
        budget: DecodeBudget,
        frames_decoded: int,
        bytes_allocated: int,
        requested_frames: int,
        requested_bytes: int,
        result_usable: bool = False,
    ) -> None:
        super().__init__(message)
        self.budget = budget
        self.frames_decoded = frames_decoded
        self.bytes_allocated = bytes_allocated
        self.requested_frames = requested_frames
        self.requested_bytes = requested_bytes
        self.result_usable = result_usable


@dataclass
class DecodeBudget:
    """A budget for a single pixel data decode operation.

    .. versionadded:: 3.1

    The budget limits the number of frames that are actually expanded and the
    number of bytes allocated for the decoded output. Both
    :func:`~pydicom.pixels.pixel_array` (whole array) and
    :func:`~pydicom.pixels.iter_pixels` (per-frame preview) accept a budget and
    account against the same counters, so switching entry points cannot bypass
    the limit.

    A budget object is stateful: its counters accumulate across the operation it
    is passed to. Create a new instance for each independent operation. Either
    limit may be left as ``None`` to leave that dimension unbounded; passing
    neither limit is equivalent to disabling the budget.

    Parameters
    ----------
    max_frames : int | None, optional
        The maximum number of frames that may be fully decoded. Must be greater
        than or equal to 0. ``None`` (default) means no frame limit.
    max_bytes : int | None, optional
        The maximum number of bytes that may be allocated for decoded output.
        Must be greater than or equal to 0. ``None`` (default) means no byte
        limit.

    Examples
    --------
    Limit a preview to at most two frames and 1 MiB of output::

        from pydicom.pixels import DecodeBudget, iter_pixels

        budget = DecodeBudget(max_frames=2, max_bytes=1024 * 1024)
        for frame in iter_pixels("path/to/dataset.dcm", budget=budget):
            ...
    """

    max_frames: int | None = None
    max_bytes: int | None = None
    frames_used: int = 0
    bytes_used: int = 0

    def __post_init__(self) -> None:
        for name, value in (
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("frames_used", self.frames_used),
            ("bytes_used", self.bytes_used),
        ):
            if value is not None and (isinstance(value, bool) or value < 0):
                raise ValueError(
                    f"'{name}' must be greater than or equal to 0, not {value!r}"
                )

    @property
    def frames_remaining(self) -> int | None:
        """Return the number of frames left, or ``None`` if unbounded."""
        if self.max_frames is None:
            return None

        return max(self.max_frames - self.frames_used, 0)

    @property
    def bytes_remaining(self) -> int | None:
        """Return the number of bytes left, or ``None`` if unbounded."""
        if self.max_bytes is None:
            return None

        return max(self.max_bytes - self.bytes_used, 0)

    @property
    def exhausted(self) -> bool:
        """Return ``True`` if either limit has been reached."""
        if self.max_frames is not None and self.frames_used >= self.max_frames:
            return True

        return self.max_bytes is not None and self.bytes_used >= self.max_bytes

    def fits(self, *, frames: int = 1, nbytes: int = 0) -> bool:
        """Return ``True`` if `frames` and `nbytes` are within the limits."""
        return (
            self.max_frames is None or self.frames_used + frames <= self.max_frames
        ) and (self.max_bytes is None or self.bytes_used + nbytes <= self.max_bytes)

    def check(
        self, *, frames: int = 1, nbytes: int = 0, result_usable: bool = False
    ) -> None:
        """Check whether `frames` and `nbytes` can be accounted for.

        The counters are not updated. This method is used before decoding or
        allocating so that a decode can stop before doing more work.

        Parameters
        ----------
        frames : int, optional
            The number of additional frames the operation needs.
        nbytes : int, optional
            The number of additional bytes the operation needs.
        result_usable : bool, optional
            Set in the raised exception as the value of
            :attr:`DecodeBudgetExceeded.result_usable`.

        Raises
        ------
        DecodeBudgetExceeded
            If accounting for `frames` and `nbytes` would exceed either limit.
        """
        if self.fits(frames=frames, nbytes=nbytes):
            return

        reasons = []
        if self.max_frames is not None and self.frames_used + frames > self.max_frames:
            reasons.append(
                f"frames (used {self.frames_used}, requested {frames}, "
                f"maximum {self.max_frames})"
            )
        if self.max_bytes is not None and self.bytes_used + nbytes > self.max_bytes:
            reasons.append(
                f"bytes (used {self.bytes_used}, requested {nbytes}, "
                f"maximum {self.max_bytes})"
            )

        raise DecodeBudgetExceeded(
            "Unable to continue decoding pixel data as the decode budget would be "
            f"exceeded for {' and '.join(reasons)}",
            budget=self,
            frames_decoded=self.frames_used,
            bytes_allocated=self.bytes_used,
            requested_frames=frames,
            requested_bytes=nbytes,
            result_usable=result_usable,
        )

    def commit(self, *, frames: int = 1, nbytes: int = 0) -> None:
        """Account for `frames` and `nbytes` that have been completed."""
        self.frames_used += frames
        self.bytes_used += nbytes

    def reset(self) -> None:
        """Reset the used counters to 0, keeping the configured limits."""
        self.frames_used = 0
        self.bytes_used = 0

    def __bool__(self) -> bool:
        """Return ``False`` if both limits are ``None``, otherwise ``True``."""
        return self.max_frames is not None or self.max_bytes is not None

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(max_frames={self.max_frames!r}, "
            f"max_bytes={self.max_bytes!r}, frames_used={self.frames_used!r}, "
            f"bytes_used={self.bytes_used!r})"
        )
