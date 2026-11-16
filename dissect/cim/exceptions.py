from __future__ import annotations


class Error(Exception):
    pass


class ReferenceNotFoundError(Error):
    pass


class InvalidDatabaseError(Error):
    pass


class ObjectDataError(Error):
    """Raised when object metadata is inconsistent or an object can not be reconstructed."""


class InvalidObjectError(ObjectDataError):
    """Raised when the TOC and index disagree about an object's location or length."""


class ObjectLengthError(InvalidObjectError):
    """Raised when the index-declared object length and the TOC entry size disagree."""

    def __init__(self, record_id: int, page: int, toc_size: int, index_length: int):
        self.record_id = record_id
        self.page = page
        self.logical_page = page
        self.toc_size = toc_size
        self.index_length = index_length

        super().__init__(
            f"TOC size {toc_size} for record id {record_id} on logical page {page} "
            f"does not match index length {index_length}"
        )


class DuplicateRecordIdError(InvalidObjectError):
    """Raised when a page TOC contains more than one entry for the requested record id."""

    def __init__(self, record_id: int, page: int, count: int = 2):
        self.record_id = record_id
        self.page = page
        self.logical_page = page
        self.count = count

        super().__init__(f"Multiple TOC entries for record id {record_id} on logical page {page}")


class RecordNotFoundError(InvalidObjectError):
    """Raised when no TOC entry exists for the requested record id."""

    def __init__(self, record_id: int, page: int):
        self.record_id = record_id
        self.page = page
        self.logical_page = page

        super().__init__(f"No TOC entry for record id {record_id} on logical page {page}")


class UnmappedPageError(ObjectDataError):
    """Raised when a logical page has no valid physical mapping."""

    def __init__(self, page: int | None = None, message: str | None = None):
        self.page = page
        self.logical_page = page

        if message is None:
            message = f"Unmapped page: {page}"

        super().__init__(message)


class ShortReadError(ObjectDataError):
    """Raised when the input does not contain all bytes required for an object or page."""

    def __init__(
        self,
        page: int,
        expected: int,
        actual: int,
        object_start: int | None = None,
        object_end: int | None = None,
    ):
        self.page = page
        self.logical_page = page
        self.expected = expected
        self.actual = actual
        self.object_start = object_start
        self.object_end = object_end
        self.object_range = (object_start, object_end) if object_start is not None else None
        self.missing_pages = (page,)
        self.missing_logical_pages = self.missing_pages
        self.missing_ranges = ((page, page),)
        self.missing_logical_ranges = self.missing_ranges
        self.missing_start = page
        self.missing_end = page
        self.missing_logical_start = page
        self.missing_logical_end = page

        location = f" for object starting at logical page {object_start}" if object_start is not None else ""
        super().__init__(f"Short read of logical page {page}{location}: expected {expected} bytes, got {actual}")


class MissingObjectDataError(UnmappedPageError):
    """Raised when an object can not be reassembled because logical pages are missing."""

    def __init__(
        self,
        object_start: int,
        object_end: int,
        missing_pages: list[int] | tuple[int, ...],
        reason: str | None = None,
    ):
        self.object_start = object_start
        self.object_end = object_end
        self.object_range = (object_start, object_end)
        self.object_logical_range = self.object_range
        self.missing_pages = tuple(sorted(set(missing_pages)))
        self.missing_logical_pages = self.missing_pages
        self.missing_ranges = tuple(_contiguous_ranges(self.missing_pages))
        self.missing_logical_ranges = self.missing_ranges
        self.missing_start = self.missing_pages[0] if self.missing_pages else None
        self.missing_end = self.missing_pages[-1] if self.missing_pages else None
        self.missing_logical_start = self.missing_start
        self.missing_logical_end = self.missing_end

        missing = _format_page_ranges(self.missing_ranges)
        object_range = _format_page_range(object_start, object_end)
        detail = f" ({reason})" if reason else ""

        super().__init__(
            self.missing_start,
            message=f"Missing {missing}{detail} while reassembling object spanning logical pages {object_range}",
        )


def _contiguous_ranges(pages: tuple[int, ...]) -> list[tuple[int, int]]:
    if not pages:
        return []

    ranges = []
    start = end = pages[0]
    for page in pages[1:]:
        if page == end + 1:
            end = page
            continue

        ranges.append((start, end))
        start = end = page
    ranges.append((start, end))

    return ranges


def _format_page_range(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def _format_page_ranges(ranges: tuple[tuple[int, int], ...] | list[tuple[int, int]]) -> str:
    if not ranges:
        return "logical pages"

    label = "logical page" if len(ranges) == 1 and ranges[0][0] == ranges[0][1] else "logical pages"
    return f"{label} {', '.join(_format_page_range(start, end) for start, end in ranges)}"
