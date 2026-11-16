"""Per-document budget for the output produced while decoding PDF streams.

PDF streams can carry a chain of filters (e.g. ASCII85 followed by Flate)
and predictors, each of which may expand the data dramatically. A small
encoded file can therefore force a decoder to allocate an amount of memory
that is only bounded by the attacker's imagination. The classes in this
module track the cumulative number of bytes produced while a whole
:class:`~pdfminer.pdfdocument.PDFDocument` is processed and additionally
cap the output of each individual decoding step.

The budget is charged incrementally, *before* the output is materialized,
so a decoding path that cannot be bounded up front must raise instead of
allocating first and checking the length afterwards.
"""

from pdfminer.pdfexceptions import PDFException


class PDFDecodeBudgetExceeded(PDFException):
    """Raised when a decoding step would exceed the configured budget.

    The message always names the decoding layer (filter or predictor)
    that exhausted the budget so callers can tell which stage stopped.
    """


class DecodeBudget:
    """Tracks decoded output across all streams of one document.

    Two independent limits are enforced:

    * ``step_limit`` caps the output of a single decoding step, i.e. one
      filter application or one predictor restoration, even when the
      decoder emits its output in many small chunks.
    * ``total_limit`` caps the sum of everything produced while the
      document is processed.

    A decoding step is opened with :meth:`begin_step` and may then charge
    its output one chunk at a time via :meth:`charge`. Re-reading an
    already decoded stream never reaches the decoders again (the result
    is cached on the :class:`~pdfminer.pdftypes.PDFStream`), so cached
    output is not charged a second time.

    :param total_limit: maximum number of bytes that may be produced in
        total by every decoding step of the document. ``None`` means no
        cumulative limit.
    :param step_limit: maximum number of bytes that a single decoding
        step may produce. ``None`` means no per-step limit.
    """

    def __init__(
        self,
        total_limit: int | None = None,
        step_limit: int | None = None,
    ) -> None:
        if total_limit is not None and total_limit < 0:
            raise ValueError("total_limit must be non-negative or None")
        if step_limit is not None and step_limit < 0:
            raise ValueError("step_limit must be non-negative or None")
        self.total_limit = total_limit
        self.step_limit = step_limit
        self.total_consumed = 0
        self.step_consumed = 0

    def __repr__(self) -> str:
        return (
            f"DecodeBudget(total_limit={self.total_limit!r}, "
            f"step_limit={self.step_limit!r}, "
            f"total_consumed={self.total_consumed!r})"
        )

    def remaining(self) -> int | None:
        """Number of bytes still chargeable against the total budget."""
        if self.total_limit is None:
            return None
        return self.total_limit - self.total_consumed

    def begin_step(self, layer: str) -> None:
        """Reset the per-step counter for a new decoding step.

        :param layer: name of the filter or predictor step; it is kept
            for API symmetry with :meth:`charge` and aids readability at
            call sites.
        """
        self.step_consumed = 0

    def check(self, layer: str, size: int) -> None:
        """Validate that ``size`` more bytes may be produced by ``layer``.

        Only inspects the limits, it does not charge anything. The
        per-step limit is evaluated against the whole step, including
        chunks charged earlier in the same step.
        """
        if size < 0:
            raise ValueError("decoded size must be non-negative")
        if self.step_limit is not None and self.step_consumed + size > self.step_limit:
            raise PDFDecodeBudgetExceeded(
                f"{layer} would produce {self.step_consumed + size} bytes, "
                f"exceeding the per-step decoding budget of "
                f"{self.step_limit} bytes"
            )
        remaining = self.remaining()
        if remaining is not None and size > remaining:
            raise PDFDecodeBudgetExceeded(
                f"{layer} needs {size} more bytes but only {remaining} "
                f"bytes remain of the document decoding budget "
                f"(total limit {self.total_limit} bytes, "
                f"{self.total_consumed} bytes already consumed)"
            )

    def charge(self, layer: str, size: int) -> None:
        """Charge ``size`` bytes of output produced by ``layer``."""
        self.check(layer, size)
        self.step_consumed += size
        self.total_consumed += size
