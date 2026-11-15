from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.database.bbolt.c_bbolt import PageFlag, c_bbolt

if TYPE_CHECKING:
    from typing import BinaryIO

MAGIC = int(c_bbolt.Magic)
"""The bbolt meta page magic value."""

VERSION = 2
"""The bbolt database layout version supported by this implementation."""

META_SIZE = len(c_bbolt.Meta)
"""Size of a bbolt meta page, including the page header."""

META_CHECKSUM_OFFSET = META_SIZE - 8
"""Offset of the checksum field within a meta page."""

META_CHECKSUM_START = 16
"""First byte covered by the meta checksum (after the page header)."""

SUPPORTED_PAGE_SIZES = (1024, 2048, 4096, 8192, 16384, 32768, 65536)
"""Page sizes that can be probed when the first meta page is damaged."""

NO_FREELIST = 0xFFFFFFFFFFFFFFFF
"""Sentinel used by bbolt when the meta page does not reference a freelist page."""

PAGE_HEADER_SIZE = 16
LEAF_ELEMENT_SIZE = 16
INLINE_BUCKET_HEADER_SIZE = 16
INLINE_BUCKET_PAGE_OFFSET = 16

_MAX_DEPTH = 256
_MAX_PROBLEMS = 32
_MAX_WARNINGS = 32


def fnv1a_64(data: bytes) -> int:
    """Return the 64-bit FNV-1a hash of *data*.

    bbolt stores an FNV-1a checksum of the meta fields (``magic`` through
    ``txid``) in the meta page. The page header is not part of the checksum.
    """
    value = 0xCBF29CE484222325
    for byte in data:
        value ^= byte
        value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


def _int(value: Any) -> int:
    return int(value)


def _read_exact(fh: BinaryIO, offset: int, size: int) -> bytes | None:
    try:
        fh.seek(offset)
        data = fh.read(size)
    except (OSError, ValueError):
        return None
    if data is None or len(data) != size:
        return None
    return data


def _file_size(fh: BinaryIO) -> int:
    fh.seek(0, 2)
    return fh.tell()


def _looks_like_meta(fh: BinaryIO, offset: int, index: int) -> bool:
    """Return whether a meta page for *index* appears to start at *offset*.

    Only structural identity is checked here. Checksums and page graph validity
    are validated separately, so a damaged but recognisable meta page still
    lets the page size of the file be established.
    """
    raw = _read_exact(fh, offset, META_SIZE)
    if raw is None:
        return False
    page_id, flags, count, overflow = struct.unpack_from("<QHHI", raw, 0)
    magic, version = struct.unpack_from("<II", raw, 16)
    return (
        page_id == index
        and flags == int(PageFlag.Meta)
        and count == 0
        and overflow == 0
        and magic == MAGIC
        and version == VERSION
    )


@dataclass(frozen=True, slots=True)
class MetaCandidate:
    """A single on-disk bbolt meta page and the result of validating it.

    Candidates are always reported, even when they are not usable. This makes
    it possible for a caller to see why a particular meta page was rejected
    instead of only observing that the database opened successfully.

    Attributes:
        index: Meta page index, ``0`` or ``1``.
        offset: File offset of the meta page, or ``None`` if it could not be located.
        present: Whether a complete meta page was available at :attr:`offset`.
        meta: Parsed meta structure, if a complete page was available.
        problems: Reasons this candidate cannot be used as a snapshot.
        warnings: Integrity observations that do not invalidate the candidate.
        checksum_stored: Checksum value stored in the meta page.
        checksum_computed: Checksum calculated from the meta fields.
        checksum_verified: Whether the stored checksum is present and matches.
        reachable_pages: Number of live pages found while validating the page graph.
    """

    index: int
    offset: int | None
    present: bool
    meta: c_bbolt.Meta | None = None
    problems: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    checksum_stored: int | None = None
    checksum_computed: int | None = None
    checksum_verified: bool = False
    reachable_pages: int = 0

    @property
    def valid(self) -> bool:
        """Whether this candidate is a complete, internally consistent snapshot."""
        return self.present and self.meta is not None and not self.problems

    @property
    def txid(self) -> int | None:
        """Transaction id of this candidate, if it was parsed."""
        return _int(self.meta.txid) if self.meta is not None else None

    @property
    def page_size(self) -> int | None:
        """Page size claimed by this candidate."""
        return _int(self.meta.pageSize) if self.meta is not None else None

    @property
    def root(self) -> int | None:
        """Root bucket page id claimed by this candidate."""
        return _int(self.meta.root.root) if self.meta is not None else None

    @property
    def root_sequence(self) -> int | None:
        """Sequence number of the root bucket."""
        return _int(self.meta.root.sequence) if self.meta is not None else None

    @property
    def high_water(self) -> int | None:
        """Page high water mark (the ``pgid`` field) claimed by this candidate."""
        return _int(self.meta.pgid) if self.meta is not None else None

    @property
    def freelist(self) -> int | None:
        """Freelist page id claimed by this candidate."""
        return _int(self.meta.freelist) if self.meta is not None else None

    @property
    def view(self) -> tuple[int, int, int, int, int] | None:
        """The transaction view described by this candidate.

        Two candidates with the same view describe the same pages: they agree
        on the page size, root bucket page, root bucket sequence, freelist page
        and page high water mark. The transaction id is deliberately excluded
        so an otherwise identical newer commit is still recognised as the same
        view. Candidates that differ in any of these fields offer conflicting
        explanations of the file and must not be combined.
        """
        if self.meta is None:
            return None
        return (
            _int(self.meta.pageSize),
            _int(self.meta.root.root),
            _int(self.meta.root.sequence),
            _int(self.meta.freelist),
            _int(self.meta.pgid),
        )

    def summary(self) -> str:
        """Return a short, human readable description of this candidate."""
        if not self.present or self.meta is None:
            return f"meta[{self.index}]: unavailable"

        if self.valid:
            state = "valid"
        elif self.problems:
            state = "rejected"
        else:
            state = "unknown"

        details = [
            f"txid={self.txid}",
            f"page_size={self.page_size}",
            f"root={self.root}",
            f"high_water={self.high_water}",
        ]
        if self.checksum_verified:
            details.append("checksum=verified")
        elif self.checksum_stored is not None:
            details.append("checksum=unverified")
        if self.reachable_pages:
            details.append(f"live_pages={self.reachable_pages}")

        return f"meta[{self.index}]: {state} ({', '.join(details)})"

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable representation of this candidate."""
        return {
            "index": self.index,
            "offset": self.offset,
            "present": self.present,
            "valid": self.valid,
            "txid": self.txid,
            "page_size": self.page_size,
            "root": self.root,
            "root_sequence": self.root_sequence,
            "high_water": self.high_water,
            "freelist": self.freelist,
            "checksum_stored": self.checksum_stored,
            "checksum_computed": self.checksum_computed,
            "checksum_verified": self.checksum_verified,
            "reachable_pages": self.reachable_pages,
            "problems": list(self.problems),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class MetaSelection:
    """The outcome of choosing between the two bbolt meta pages.

    Attributes:
        candidates: Both inspected meta candidates, in page order.
        selected: The candidate whose transaction view must be used, or ``None``
            when no candidate can be trusted or the candidates cannot be
            reconciled.
        status: One of ``"selected"``, ``"conflict"`` or ``"unavailable"``.
        reason: Explanation of the decision.
        page_size: Page size established for this database file.
        file_size: Size of the database file in bytes.
    """

    candidates: tuple[MetaCandidate, ...]
    selected: MetaCandidate | None
    status: str
    reason: str
    page_size: int | None
    file_size: int
    warnings: tuple[str, ...] = ()

    @property
    def selected_index(self) -> int | None:
        """Index of the selected meta page, if one was selected."""
        return self.selected.index if self.selected is not None else None

    @property
    def txid(self) -> int | None:
        """Transaction id of the selected snapshot, if one was selected."""
        return self.selected.txid if self.selected is not None else None

    @property
    def other(self) -> MetaCandidate | None:
        """The candidate that was not selected, if one was selected."""
        if self.selected is None:
            return None
        for candidate in self.candidates:
            if candidate.index != self.selected.index:
                return candidate
        return None

    def _candidate_line(self, candidate: MetaCandidate) -> str:
        line = candidate.summary()
        if self.selected is not None and candidate.index == self.selected.index:
            return f"  {line}; selected: {self.reason}"

        if self.selected is None:
            if candidate.problems:
                return f"  {line}; rejected: {'; '.join(candidate.problems)}"
            return f"  {line}; not selected: {self.reason}"

        if candidate.valid:
            return f"  {line}; not selected: {_reason_not_selected(self.selected, candidate)}"
        return f"  {line}; not selected: {'; '.join(candidate.problems) or 'invalid'}"

    def explain(self) -> str:
        """Return a human readable explanation suitable for an investigation report."""
        if self.selected is not None:
            header = (
                f"selected meta[{self.selected.index}] "
                f"(txid={self.selected.txid}, page_size={self.page_size}, "
                f"root={self.selected.root}, high_water={self.selected.high_water}): {self.reason}"
            )
        else:
            header = f"no bbolt snapshot selected: {self.reason}"

        lines = [header, *(self._candidate_line(candidate) for candidate in self.candidates)]
        lines.extend(f"warning: {warning}" for warning in self.warnings)
        return "\n".join(lines)

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable representation of the selection and its evidence."""
        return {
            "status": self.status,
            "reason": self.reason,
            "selected_index": self.selected_index,
            "selected_txid": self.txid,
            "page_size": self.page_size,
            "file_size": self.file_size,
            "candidates": [candidate.as_dict() for candidate in self.candidates],
            "warnings": list(self.warnings),
            "explanation": self.explain(),
        }


def _reason_not_selected(selected: MetaCandidate, candidate: MetaCandidate) -> str:
    if candidate.txid is None:
        return "candidate is incomplete"
    if selected.txid is not None and candidate.txid < selected.txid:
        return f"older transaction (txid {candidate.txid} < selected txid {selected.txid})"
    if selected.txid is not None and candidate.txid > selected.txid:
        return f"newer transaction (txid {candidate.txid} > selected txid {selected.txid})"
    if candidate.view != selected.view:
        return "valid but describes a conflicting transaction view"
    return "valid but redundant with the selected candidate"


def _add(items: list[str], message: str, limit: int = _MAX_PROBLEMS) -> None:
    if len(items) < limit:
        items.append(message)


class _PageGraphValidator:
    """Validate the live page graph reachable from a root bucket."""

    def __init__(self, fh: BinaryIO, file_size: int, page_size: int, high_water: int) -> None:
        self.fh = fh
        self.file_size = file_size
        self.page_size = page_size
        self.high_water = high_water
        self.problems: list[str] = []
        self.warnings: list[str] = []
        self.seen: set[int] = set()
        self.covered: set[int] = set()
        self.reachable = 0

    def validate(self, root: int) -> None:
        if not 2 <= root < self.high_water:
            _add(self.problems, f"root bucket page {root} is outside the page high water mark ({self.high_water})")
            return
        self._walk_page(root, expected_first_key=None, depth=0)

    def _read_page(self, pgid: int) -> tuple[bytes, int] | None:
        if pgid < 2 or pgid >= self.high_water:
            _add(self.problems, f"page {pgid} is outside the transaction view [2, {self.high_water})")
            return None

        header = _read_exact(self.fh, pgid * self.page_size, PAGE_HEADER_SIZE)
        if header is None:
            _add(self.problems, f"page {pgid} header is outside the file")
            return None

        page_id, flags, count, overflow = struct.unpack_from("<QHHI", header, 0)
        if page_id != pgid:
            _add(self.problems, f"page {pgid} header id is {page_id}")
        if flags not in (int(PageFlag.Leaf), int(PageFlag.Branch)):
            _add(self.problems, f"page {pgid} has unsupported flags {flags:#x}")
            return None
        if pgid + 1 + overflow > self.high_water:
            _add(
                self.problems,
                f"page {pgid} with overflow {overflow} crosses the page high water mark ({self.high_water})",
            )
            return None

        span = (1 + overflow) * self.page_size
        if pgid * self.page_size + span > self.file_size:
            _add(self.problems, f"page {pgid} with overflow {overflow} extends beyond the file")
            return None
        if PAGE_HEADER_SIZE + count * LEAF_ELEMENT_SIZE > span:
            _add(self.problems, f"page {pgid} declares {count} elements that do not fit in its page span")
            return None

        data = _read_exact(self.fh, pgid * self.page_size, span)
        if data is None:
            _add(self.problems, f"page {pgid} could not be read completely")
            return None
        return data, count

    def _walk_page(self, pgid: int, expected_first_key: bytes | None, depth: int) -> bytes | None:
        if depth > _MAX_DEPTH:
            _add(self.problems, f"page graph is deeper than {_MAX_DEPTH} pages at page {pgid}")
            return None
        if pgid in self.seen:
            _add(self.problems, f"page {pgid} is referenced more than once (transaction view is not a tree)")
            return None
        if pgid in self.covered:
            _add(self.problems, f"page {pgid} lies inside another page's overflow range")
            return None

        result = self._read_page(pgid)
        if result is None:
            return None

        self.seen.add(pgid)
        self.reachable += 1

        data, count = result
        overflow = struct.unpack_from("<I", data, 12)[0]
        span_pages = range(pgid + 1, pgid + 1 + overflow)
        if any(page in self.covered for page in span_pages):
            _add(self.problems, f"page {pgid} overflow range overlaps another live page")
            return None
        self.covered.update(range(pgid, pgid + 1 + overflow))
        flags = struct.unpack_from("<H", data, 8)[0]
        first_key: bytes | None = None
        previous_key: bytes | None = None

        for index in range(count):
            element_offset = PAGE_HEADER_SIZE + index * LEAF_ELEMENT_SIZE
            if flags == int(PageFlag.Branch):
                pos, ksize, child = struct.unpack_from("<IIQ", data, element_offset)
                key = self._element_bytes(data, element_offset, pos, ksize, count, index, pgid, "branch key")
                if key is None:
                    return None
                if previous_key is not None and key <= previous_key:
                    _add(self.warnings, f"page {pgid} branch keys are not strictly increasing at element {index}")
                previous_key = key
                if first_key is None:
                    first_key = key
                if index == 0 and expected_first_key is not None and key != expected_first_key:
                    _add(
                        self.warnings,
                        f"page {pgid} first branch key {key!r} does not match parent separator {expected_first_key!r}",
                    )
                if not 2 <= child < self.high_water:
                    _add(self.problems, f"page {pgid} branch element {index} points outside the view to page {child}")
                    return None
                child_first = self._walk_page(child, expected_first_key=key, depth=depth + 1)
                if child_first is not None and child_first != key:
                    _add(
                        self.warnings,
                        f"page {pgid} separator key {key!r} does not match "
                        f"child page {child} first key {child_first!r}",
                    )
            else:
                leaf_flags, pos, ksize, vsize = struct.unpack_from("<IIII", data, element_offset)
                key = self._element_bytes(data, element_offset, pos, ksize, count, index, pgid, "leaf key")
                if key is None:
                    return None
                value_offset = element_offset + pos + ksize
                if value_offset + vsize > len(data):
                    _add(self.problems, f"page {pgid} leaf element {index} value extends beyond its page")
                    return None
                value = data[value_offset : value_offset + vsize]
                if previous_key is not None and key <= previous_key:
                    _add(self.warnings, f"page {pgid} leaf keys are not strictly increasing at element {index}")
                previous_key = key
                if first_key is None:
                    first_key = key
                if index == 0 and expected_first_key is not None and key != expected_first_key:
                    _add(
                        self.warnings,
                        f"page {pgid} first leaf key {key!r} does not match parent separator {expected_first_key!r}",
                    )

                if leaf_flags not in (0, 1):
                    _add(self.problems, f"page {pgid} leaf element {index} has unsupported flags {leaf_flags:#x}")
                    continue
                if leaf_flags == 1:
                    self._walk_bucket_value(value, pgid, index, depth)

        return first_key

    def _element_bytes(
        self,
        data: bytes,
        element_offset: int,
        pos: int,
        ksize: int,
        count: int,
        index: int,
        pgid: int,
        kind: str,
    ) -> bytes | None:
        minimum_pos = (count - index) * LEAF_ELEMENT_SIZE
        if pos < minimum_pos:
            _add(self.problems, f"page {pgid} {kind} element {index} overlaps the element table")
            return None
        key_offset = element_offset + pos
        key_end = key_offset + ksize
        if key_end > len(data):
            _add(self.problems, f"page {pgid} {kind} element {index} extends beyond its page")
            return None
        return data[key_offset:key_end]

    def _walk_bucket_value(self, value: bytes, pgid: int, index: int, depth: int) -> None:
        if len(value) < INLINE_BUCKET_HEADER_SIZE:
            _add(self.problems, f"page {pgid} bucket element {index} has a truncated bucket header")
            return

        root, _sequence = struct.unpack_from("<QQ", value, 0)
        if root == 0:
            inline = value[INLINE_BUCKET_PAGE_OFFSET:]
            self._walk_inline_page(inline, pgid, index, depth + 1)
        elif not 2 <= root < self.high_water:
            _add(
                self.problems,
                f"page {pgid} bucket element {index} has root page {root} outside the view",
            )
        else:
            self._walk_page(root, expected_first_key=None, depth=depth + 1)

    def _walk_inline_page(self, inline: bytes, pgid: int, index: int, depth: int) -> None:
        if depth > _MAX_DEPTH:
            _add(self.problems, f"inline bucket on page {pgid} element {index} is nested too deeply")
            return
        if len(inline) < PAGE_HEADER_SIZE:
            _add(self.problems, f"page {pgid} bucket element {index} has a truncated inline page")
            return

        page_id, flags, count, overflow = struct.unpack_from("<QHHI", inline, 0)
        if page_id != 0:
            _add(self.warnings, f"page {pgid} inline bucket element {index} has page id {page_id}")
        if flags not in (int(PageFlag.Leaf), int(PageFlag.Branch)):
            _add(self.problems, f"page {pgid} inline bucket element {index} has unsupported flags {flags:#x}")
            return
        if overflow != 0:
            _add(self.problems, f"page {pgid} inline bucket element {index} declares overflow pages")
            return
        if PAGE_HEADER_SIZE + count * LEAF_ELEMENT_SIZE > len(inline):
            _add(self.problems, f"page {pgid} inline bucket element {index} has too many elements")
            return

        previous_key: bytes | None = None
        for element in range(count):
            element_offset = PAGE_HEADER_SIZE + element * LEAF_ELEMENT_SIZE
            if flags == int(PageFlag.Branch):
                pos, ksize, child = struct.unpack_from("<IIQ", inline, element_offset)
                key = self._inline_element_bytes(
                    inline, element_offset, pos, ksize, count, element, pgid, index, "branch key"
                )
                if key is None:
                    return
                if previous_key is not None and key <= previous_key:
                    _add(self.warnings, f"inline bucket on page {pgid} element {index} branch keys are unsorted")
                previous_key = key
                if not 2 <= child < self.high_water:
                    _add(
                        self.problems,
                        f"inline bucket on page {pgid} element {index} branch points outside the view to page {child}",
                    )
                    return
                self._walk_page(child, expected_first_key=key, depth=depth + 1)
            else:
                leaf_flags, pos, ksize, vsize = struct.unpack_from("<IIII", inline, element_offset)
                key = self._inline_element_bytes(
                    inline, element_offset, pos, ksize, count, element, pgid, index, "leaf key"
                )
                if key is None:
                    return
                value_offset = element_offset + pos + ksize
                if value_offset + vsize > len(inline):
                    _add(self.problems, f"inline bucket on page {pgid} element {index} leaf value is out of bounds")
                    return
                value = inline[value_offset : value_offset + vsize]
                if previous_key is not None and key <= previous_key:
                    _add(self.warnings, f"inline bucket on page {pgid} element {index} leaf keys are unsorted")
                previous_key = key
                if leaf_flags not in (0, 1):
                    _add(
                        self.problems,
                        f"inline bucket on page {pgid} element {index} leaf flags {leaf_flags:#x} are unsupported",
                    )
                    continue
                if leaf_flags == 1:
                    self._walk_bucket_value(value, pgid, index, depth)

    def _inline_element_bytes(
        self,
        inline: bytes,
        element_offset: int,
        pos: int,
        ksize: int,
        count: int,
        element: int,
        pgid: int,
        bucket_index: int,
        kind: str,
    ) -> bytes | None:
        minimum_pos = (count - element) * LEAF_ELEMENT_SIZE
        if pos < minimum_pos:
            _add(
                self.problems,
                f"inline bucket on page {pgid} element {bucket_index} {kind} {element} overlaps the element table",
            )
            return None
        key_offset = element_offset + pos
        key_end = key_offset + ksize
        if key_end > len(inline):
            _add(
                self.problems,
                f"inline bucket on page {pgid} element {bucket_index} {kind} {element} is out of bounds",
            )
            return None
        return inline[key_offset:key_end]


def _validate_freelist(
    fh: BinaryIO, file_size: int, page_size: int, high_water: int, freelist: int, live_pages: set[int]
) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    warnings: list[str] = []
    if freelist == NO_FREELIST:
        return problems, warnings

    if not 2 <= freelist < high_water:
        _add(problems, f"freelist page {freelist} is outside the page high water mark ({high_water})")
        return problems, warnings

    header = _read_exact(fh, freelist * page_size, PAGE_HEADER_SIZE)
    if header is None:
        _add(problems, f"freelist page {freelist} header is outside the file")
        return problems, warnings

    page_id, flags, count, overflow = struct.unpack_from("<QHHI", header, 0)
    if page_id != freelist:
        _add(warnings, f"freelist page {freelist} header id is {page_id}")
    if flags != int(PageFlag.Freelist):
        _add(warnings, f"freelist page {freelist} has flags {flags:#x}")
    if freelist in live_pages:
        _add(problems, f"freelist page {freelist} is also reachable from the root bucket")

    span = (1 + overflow) * page_size
    if freelist * page_size + span > file_size or freelist + 1 + overflow > high_water:
        _add(warnings, f"freelist page {freelist} crosses the file or page high water mark")
        return problems, warnings

    offset = freelist * page_size + PAGE_HEADER_SIZE
    if count == 0xFFFF:
        count_data = _read_exact(fh, offset, 8)
        if count_data is None:
            _add(warnings, f"freelist page {freelist} has a truncated extended count")
            return problems, warnings
        count = struct.unpack("<Q", count_data)[0]
        offset += 8

    available = span - (offset - freelist * page_size)
    if count * 8 > available:
        _add(warnings, f"freelist page {freelist} declares {count} entries that do not fit in its page span")
        return problems, warnings

    data = _read_exact(fh, offset, count * 8)
    if data is None:
        _add(warnings, f"freelist page {freelist} entries could not be read")
        return problems, warnings

    # A freelist is not needed to read data, so this is diagnostic only. Avoid
    # spending unbounded time on a damaged list in a large database.
    for entry_index in range(min(count, 1 << 20)):
        free_page = struct.unpack_from("<Q", data, entry_index * 8)[0]
        if not 2 <= free_page < high_water:
            _add(warnings, f"freelist page {freelist} entry {entry_index} points outside the view to page {free_page}")
        elif free_page in live_pages:
            _add(warnings, f"freelist page {freelist} marks live page {free_page} as free")

    return problems, warnings


def _inspect_candidate(
    fh: BinaryIO,
    file_size: int,
    index: int,
    offset: int | None,
    page_size: int | None,
) -> MetaCandidate:
    if offset is None or offset + META_SIZE > file_size:
        return MetaCandidate(
            index=index,
            offset=offset,
            present=False,
            problems=(f"meta[{index}] page is missing or truncated",),
        )

    raw = _read_exact(fh, offset, META_SIZE)
    if raw is None:
        return MetaCandidate(
            index=index,
            offset=offset,
            present=False,
            problems=(f"meta[{index}] page could not be read",),
        )

    try:
        meta = c_bbolt.Meta(raw)
    except Exception as exc:  # pragma: no cover - defensive for malformed cstruct input
        return MetaCandidate(
            index=index,
            offset=offset,
            present=True,
            problems=(f"meta[{index}] could not be parsed: {exc}",),
        )

    problems: list[str] = []
    warnings: list[str] = []

    stored_checksum = _int(meta.checksum)
    computed_checksum = fnv1a_64(raw[META_CHECKSUM_START:META_CHECKSUM_OFFSET])
    checksum_verified = stored_checksum != 0 and stored_checksum == computed_checksum

    if _int(meta.page.id) != index:
        _add(problems, f"meta[{index}] page header id is {_int(meta.page.id)}")
    if _int(meta.page.flags) != int(PageFlag.Meta):
        _add(problems, f"meta[{index}] page header flags are {_int(meta.page.flags):#x}, not meta")
    if _int(meta.page.count) != 0 or _int(meta.page.overflow) != 0:
        _add(problems, f"meta[{index}] page header has non-zero count/overflow")
    if _int(meta.magic) != MAGIC:
        _add(problems, f"meta[{index}] magic is {_int(meta.magic):#x}, expected {MAGIC:#x}")
    if _int(meta.version) != VERSION:
        _add(problems, f"meta[{index}] version is {_int(meta.version)}, supported version is {VERSION}")

    meta_page_size = _int(meta.pageSize)
    if meta_page_size not in SUPPORTED_PAGE_SIZES:
        _add(problems, f"meta[{index}] page size {meta_page_size} is not a supported bbolt page size")
    elif page_size is None:
        _add(problems, f"meta[{index}] cannot be validated because the file page size could not be established")
    elif meta_page_size != page_size:
        _add(
            problems,
            f"meta[{index}] page size {meta_page_size} conflicts with the {page_size} byte meta page offset",
        )

    if stored_checksum == 0:
        _add(problems, f"meta[{index}] has no checksum; the snapshot cannot be verified")
    elif not checksum_verified:
        _add(
            problems,
            f"meta[{index}] checksum mismatch (stored {stored_checksum:#018x}, computed {computed_checksum:#018x})",
        )

    if _int(meta.flags) != 0:
        _add(warnings, f"meta[{index}] has unsupported meta flags {_int(meta.flags):#x}")

    high_water = _int(meta.pgid)
    root = _int(meta.root.root)
    freelist = _int(meta.freelist)

    if high_water < 2:
        _add(problems, f"meta[{index}] page high water mark {high_water} is too small")
    elif page_size is not None:
        file_pages = file_size // page_size
        if high_water > file_pages:
            _add(
                problems,
                f"meta[{index}] page high water mark {high_water} exceeds the {file_pages} pages in the file",
            )

    if not 2 <= root < high_water:
        _add(
            problems,
            f"meta[{index}] root bucket page {root} is outside [2, {high_water})",
        )

    reachable_pages = 0
    if not problems and page_size is not None:
        validator = _PageGraphValidator(fh, file_size, page_size, high_water)
        validator.validate(root)
        problems.extend(validator.problems)
        warnings.extend(validator.warnings)
        reachable_pages = validator.reachable
        freelist_problems, freelist_warnings = _validate_freelist(
            fh, file_size, page_size, high_water, freelist, validator.seen
        )
        problems.extend(freelist_problems)
        warnings.extend(freelist_warnings)

    return MetaCandidate(
        index=index,
        offset=offset,
        present=True,
        meta=meta,
        problems=tuple(problems[:_MAX_PROBLEMS]),
        warnings=tuple(warnings[:_MAX_WARNINGS]),
        checksum_stored=stored_checksum,
        checksum_computed=computed_checksum,
        checksum_verified=checksum_verified,
        reachable_pages=reachable_pages,
    )


def _derive_page_size(fh: BinaryIO, file_size: int) -> int | None:
    """Determine the file page size without trusting a single meta page.

    The second meta page is always located at the file page size, so probing
    for a recognisable second meta page at each supported power-of-two offset
    yields the page size even when the first meta page's ``pageSize`` field is
    damaged. When multiple offsets match, the value confirmed by both meta
    pages' own ``pageSize`` fields is preferred.
    """
    probes = [
        page_size
        for page_size in SUPPORTED_PAGE_SIZES
        if page_size + META_SIZE <= file_size and _looks_like_meta(fh, page_size, 1)
    ]

    if not probes:
        # The second meta page's page id may itself be damaged. A meta page at
        # offset N still identifies the page size through its own pageSize
        # field, so use structural fields plus that self-consistency.
        for page_size in SUPPORTED_PAGE_SIZES:
            if page_size + META_SIZE > file_size:
                continue
            raw = _read_exact(fh, page_size, META_SIZE)
            if raw is None:
                continue
            _page_id, flags, count, overflow = struct.unpack_from("<QHHI", raw, 0)
            magic, version = struct.unpack_from("<II", raw, 16)
            size_field = struct.unpack_from("<I", raw, 24)[0]
            if (
                flags == int(PageFlag.Meta)
                and count == 0
                and overflow == 0
                and magic == MAGIC
                and version == VERSION
                and size_field == page_size
            ):
                probes.append(page_size)

    if len(probes) == 1:
        return probes[0]

    if len(probes) > 1:
        first = _read_exact(fh, 0, META_SIZE)
        first_size = struct.unpack_from("<I", first, 24)[0] if first is not None else None

        # A meta page for index 1 must be located at its own page size. Prefer
        # offsets where that self-consistency holds, and then the value that
        # agrees with the first meta page as well.
        self_consistent = []
        for page_size in probes:
            second = _read_exact(fh, page_size, META_SIZE)
            second_size = struct.unpack_from("<I", second, 24)[0] if second is not None else None
            if second_size == page_size:
                self_consistent.append(page_size)

        for page_size in self_consistent:
            if first_size == page_size:
                return page_size
        if self_consistent:
            return self_consistent[0]
        return probes[0]

    # No recognisable second meta page. The first meta page's page size field is
    # the only remaining hint; candidates using it will still be validated.
    first = _read_exact(fh, 0, META_SIZE)
    if first is not None:
        page_size = struct.unpack_from("<I", first, 24)[0]
        if page_size in SUPPORTED_PAGE_SIZES:
            return page_size

    return None


def select_meta(fh: BinaryIO | Path) -> MetaSelection:
    """Select a trustworthy bbolt transaction view from the two meta pages.

    Both meta pages are inspected independently. A candidate is usable only if
    its page header, magic, version, page size and checksum are consistent, and
    the live page graph reachable from its root bucket stays inside the
    candidate's page high water mark. A newer candidate that fails these checks
    is rejected so the older, provably valid snapshot can be used.

    When both candidates are valid, the higher transaction id wins. If both
    describe different views at the same transaction id, no snapshot is selected:
    neither candidate can be shown to be the committed one, and mixing pages from
    the two views would fabricate a database that never existed.

    Args:
        fh: Seekable binary file handle positioned anywhere in the database.

    Returns:
        A :class:`MetaSelection` describing both candidates and the decision.
    """
    if isinstance(fh, Path):
        with fh.open("rb") as handle:
            return select_meta(handle)

    try:
        position = fh.tell()
    except (OSError, ValueError):
        position = None

    try:
        return _select_meta(fh)
    finally:
        if position is not None:
            try:
                fh.seek(position)
            except (OSError, ValueError):
                pass


def _select_meta(fh: BinaryIO) -> MetaSelection:
    file_size = _file_size(fh)
    page_size = _derive_page_size(fh, file_size)

    candidates = (
        _inspect_candidate(fh, file_size, 0, 0, page_size),
        _inspect_candidate(fh, file_size, 1, page_size, page_size),
    )
    valid = [candidate for candidate in candidates if candidate.valid]

    warnings: list[str] = []
    if (
        page_size is not None
        and len(candidates) == 2
        and all(candidate.page_size is not None for candidate in candidates)
        and len({candidate.page_size for candidate in candidates}) > 1
    ):
        warnings.append("the two meta pages disagree on the database page size")

    if not valid:
        if all(not candidate.present for candidate in candidates):
            reason = "neither meta page is present in the file"
        else:
            reason = "both meta candidates are unusable; every candidate failed integrity validation"
        return MetaSelection(
            candidates=candidates,
            selected=None,
            status="unavailable",
            reason=reason,
            page_size=page_size,
            file_size=file_size,
            warnings=tuple(warnings),
        )

    if len(valid) == 1:
        selected = valid[0]
        other = candidates[1 - selected.index]
        if not other.present:
            reason = f"meta[{other.index}] is missing; using the only complete verified snapshot (txid {selected.txid})"
        elif other.txid is not None and selected.txid is not None and other.txid > selected.txid:
            reason = (
                f"newer meta[{other.index}] (txid {other.txid}) failed integrity validation; "
                f"falling back to the older verified snapshot (txid {selected.txid})"
            )
        else:
            reason = (
                f"meta[{other.index}] failed integrity validation; using the verified snapshot (txid {selected.txid})"
            )
        return MetaSelection(
            candidates=candidates,
            selected=selected,
            status="selected",
            reason=reason,
            page_size=page_size,
            file_size=file_size,
            warnings=tuple(warnings),
        )

    first, second = valid
    if first.txid != second.txid:
        selected, other = (first, second) if (first.txid or 0) > (second.txid or 0) else (second, first)
        return MetaSelection(
            candidates=candidates,
            selected=selected,
            status="selected",
            reason=(
                f"newest verified transaction (txid {selected.txid}); "
                f"the other candidate is a valid but stale snapshot (txid {other.txid})"
            ),
            page_size=page_size,
            file_size=file_size,
            warnings=tuple(warnings),
        )

    if first.view == second.view:
        return MetaSelection(
            candidates=candidates,
            selected=first,
            status="selected",
            reason="both candidates describe the same transaction view; the lower meta index was selected",
            page_size=page_size,
            file_size=file_size,
            warnings=tuple(warnings),
        )

    return MetaSelection(
        candidates=candidates,
        selected=None,
        status="conflict",
        reason=(
            "both meta candidates are internally valid but describe conflicting transaction views "
            f"at txid {first.txid}; refusing to combine pages from different snapshots"
        ),
        page_size=page_size,
        file_size=file_size,
    )
