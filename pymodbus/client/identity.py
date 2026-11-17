"""Bounded, integrity-reporting Read Device Identification entry point.

The Read Device Identification function (function code 0x2B, MEI type 0x0E)
paginates a set of identification objects across several responses. A
malicious or broken endpoint controls the pagination hints in every response
and can:

* keep the ``More Follows`` flag asserted forever;
* return a ``Next Object Id`` that does not advance (a read loop);
* re-send objects already delivered on a previous page (segment overlap);
* answer with a different access level (read code) than the one requested;
* declare an object count that does not match the objects actually carried.

This module drives the multi-page read behind caller supplied *page* and
*total byte* limits and never turns a truncated read into a complete device
profile. Endpoint claims (the raw ``More Follows`` / ``Next Object Id``
headers) are kept separate from the pagination relationships that local
validation can actually prove.
"""

from __future__ import annotations

import enum
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..constants import DeviceInformation, MoreData
from ..pdu import ModbusPDU
from ..pdu.mei_message import (
    ReadDeviceInformationRequest,
    ReadDeviceInformationResponse,
)


#: A transport that turns one request PDU into an awaited response PDU.
#:
#: The real client plugs in its asynchronous ``execute`` method; tests plug in
#: a scripted transport double that records the requests it receives.
AsyncIdentityTransport = Callable[[ModbusPDU], Awaitable[ModbusPDU]]

#: Synchronous counterpart of :data:`AsyncIdentityTransport`.
SyncIdentityTransport = Callable[[ModbusPDU], ModbusPDU]


class IdentityConflictCode(enum.Enum):
    """Reasons a single identity read can fail local validation.

    The codes are intentionally coarse: they describe what the endpoint did,
    while the full context (page, object id, values) lives on
    :class:`IdentityConflict`.
    """

    #: Endpoint returned a Modbus exception response.
    EXCEPTION_RESPONSE = "exception_response"
    #: Response was not a Read Device Identification response.
    UNEXPECTED_RESPONSE = "unexpected_response"
    #: Access level (read code) does not match the requested one.
    ACCESS_LEVEL_CHANGED = "access_level_changed"
    #: Distinct object ids stopped increasing between pages (no progress).
    NO_PROGRESS = "no_progress"
    #: An object id already delivered on an earlier page reappeared.
    SEGMENT_OVERLAP = "segment_overlap"
    #: Declared object count differs from the number of objects parsed.
    OBJECT_COUNT_MISMATCH = "object_count_mismatch"
    #: The caller's maximum number of pages was reached.
    PAGE_LIMIT_REACHED = "page_limit_reached"
    #: The caller's maximum number of identity bytes was reached.
    BYTE_LIMIT_REACHED = "byte_limit_reached"


@dataclass(frozen=True, slots=True)
class IdentityConflict:
    """A single validation failure with enough context to act on it."""

    code: IdentityConflictCode
    page: int
    detail: str
    object_id: int | None = None


@dataclass(frozen=True, slots=True)
class IdentityObject:
    """One identification object as delivered by the endpoint.

    Repeated occurrences of the same object id are preserved: each one becomes
    its own :class:`IdentityObject`, including the page it arrived on.
    """

    object_id: int
    value: bytes
    page: int


@dataclass(frozen=True, slots=True)
class IdentityReadLimits:
    """Caller supplied bounds for a single identity read.

    Both bounds are hard stops. Reaching either one ends the read and is
    reported through :attr:`DeviceIdentityResult.complete` being ``False``;
    the objects already collected are still returned.
    """

    max_pages: int = 8
    max_identity_bytes: int = 4096

    def __post_init__(self) -> None:
        """Validate the bounds."""
        if self.max_pages < 1:
            raise ValueError("max_pages must be >= 1")
        if self.max_identity_bytes < 1:
            raise ValueError("max_identity_bytes must be >= 1")


@dataclass(frozen=True, slots=True)
class _PageEvidence:
    """Pagination evidence for one response, split claim vs. local proof."""

    page: int
    claimed_more_follows: int
    claimed_next_object_id: int
    claimed_object_count: int
    object_count: int
    #: True when the objects on this page follow straight on from the previous
    #: one with no gap relative to the ids actually delivered so far.
    locally_verified_continuation: bool


@dataclass(slots=True)
class DeviceIdentityResult:
    """Outcome of a bounded identity read.

    ``complete`` only reflects local proof. It is ``True`` solely when every
    response validated, the pages formed an advancing, non-overlapping chain,
    and the chain ended on a response whose ``More Follows`` marker announced
    the last page. A read stopped by a limit or a conflict is partial even if
    the objects already collected look like a plausible device profile.
    """

    read_code: int
    complete: bool
    pages_requested: int
    identity_bytes: int
    objects: list[IdentityObject] = field(default_factory=list)
    conflicts: list[IdentityConflict] = field(default_factory=list)
    page_evidence: list[_PageEvidence] = field(default_factory=list)
    #: Raw endpoint pagination headers, kept distinct from local proof.
    claimed_more_follows: int = MoreData.NOTHING
    claimed_next_object_id: int = 0

    @property
    def information(self) -> dict[int, bytes | list[bytes]]:
        """Collected objects keyed by id, preserving every repeated value.

        A single occurrence maps to ``bytes``; repeated ids map to a list with
        each occurrence in arrival order, mirroring how the wire decoder keeps
        duplicate objects instead of silently dropping them.
        """
        grouped: dict[int, bytes | list[bytes]] = {}
        for obj in self.objects:
            if obj.object_id not in grouped:
                grouped[obj.object_id] = obj.value
            elif isinstance(grouped[obj.object_id], list):
                grouped[obj.object_id].append(obj.value)  # type: ignore[union-attr]
            else:
                grouped[obj.object_id] = [grouped[obj.object_id], obj.value]  # type: ignore[list-item]
        return grouped

    @property
    def limit_reached(self) -> bool:
        """Return True when the read stopped on a caller bound."""
        return any(
            conflict.code
            in (
                IdentityConflictCode.PAGE_LIMIT_REACHED,
                IdentityConflictCode.BYTE_LIMIT_REACHED,
            )
            for conflict in self.conflicts
        )


def _iter_response_objects(
    response: ReadDeviceInformationResponse,
) -> list[tuple[int, bytes]]:
    """Expand a decoded response into ordered ``(object_id, value)`` pairs.

    The decoder stores repeated ids either as a single value or as a list of
    values. This flattens both shapes while preserving the on-wire order, so
    every occurrence is available for overlap and monotonicity checks.
    """
    ordered: list[tuple[int, bytes]] = []
    for object_id, value in response.information.items():
        if isinstance(value, list):
            for item in value:
                ordered.append((object_id, item))
        else:
            ordered.append((object_id, value))
    return ordered


class _IdentityReader:
    """State machine that validates and bounds one multi-page identity read."""

    def __init__(
        self,
        read_code: int,
        device_id: int,
        limits: IdentityReadLimits,
    ) -> None:
        self._read_code = read_code
        self._device_id = device_id
        self._limits = limits
        self._objects: list[IdentityObject] = []
        self._conflicts: list[IdentityConflict] = []
        self._evidence: list[_PageEvidence] = []
        self._seen_ids: set[int] = set()
        self._last_distinct_id: int | None = None
        self._pages_requested = 0
        self._identity_bytes = 0
        self._next_object_id = 0
        self._claimed_more_follows = MoreData.NOTHING
        self._claimed_next_object_id = 0
        self._chain_verified = True
        self._stop = False
        self._terminal_claim = False

    def _conflict(
        self,
        code: IdentityConflictCode,
        page: int,
        detail: str,
        *,
        object_id: int | None = None,
        fatal: bool = True,
    ) -> None:
        self._conflicts.append(
            IdentityConflict(code=code, page=page, detail=detail, object_id=object_id)
        )
        if fatal:
            self._chain_verified = False
            self._stop = True

    def _collect_page_objects(
        self, page_objects: list[tuple[int, bytes]], page: int
    ) -> tuple[set[int], bool]:
        """Merge one page's objects into the read, returning (ids, advances).

        ``advances`` is ``False`` when the page overlaps an earlier page or its
        distinct ids do not increase monotonically.
        """
        page_distinct: set[int] = set()
        advances = True
        for object_id, value in page_objects:
            self._identity_bytes += len(value)

            is_new_id = object_id not in page_distinct and object_id not in (
                self._seen_ids
            )
            if is_new_id and self._last_distinct_id is not None:
                if object_id <= self._last_distinct_id:
                    self._conflict(
                        IdentityConflictCode.NO_PROGRESS,
                        page,
                        f"object id {object_id} does not advance beyond "
                        f"{self._last_distinct_id}",
                        object_id=object_id,
                    )
                    advances = False
                else:
                    self._last_distinct_id = object_id
            elif is_new_id:
                self._last_distinct_id = object_id

            # Segment overlap is strictly cross-page: repeated values for an id
            # already seen on an earlier page. Repeats within this page are
            # legal per the protocol and are preserved, not treated as overlap.
            if object_id in self._seen_ids and object_id not in page_distinct:
                self._conflict(
                    IdentityConflictCode.SEGMENT_OVERLAP,
                    page,
                    f"object id {object_id} was already delivered on an earlier page",
                    object_id=object_id,
                    fatal=False,
                )
                advances = False

            page_distinct.add(object_id)
            self._seen_ids.add(object_id)
            self._objects.append(
                IdentityObject(object_id=object_id, value=value, page=page)
            )
        return page_distinct, advances

    def _handle_response(self, response: ModbusPDU) -> None:
        page = self._pages_requested

        if response.isError():
            self._conflict(
                IdentityConflictCode.EXCEPTION_RESPONSE,
                page,
                f"endpoint returned exception response {response!s}",
            )
            return
        if not isinstance(response, ReadDeviceInformationResponse):
            self._conflict(
                IdentityConflictCode.UNEXPECTED_RESPONSE,
                page,
                f"expected ReadDeviceInformationResponse, got {type(response).__name__}",
            )
            return

        # Record the endpoint's raw pagination claim before validating it.
        self._claimed_more_follows = response.more_follows
        self._claimed_next_object_id = response.next_object_id

        if response.read_code != self._read_code:
            self._conflict(
                IdentityConflictCode.ACCESS_LEVEL_CHANGED,
                page,
                "response read code "
                f"{response.read_code} does not match requested {self._read_code}",
                fatal=False,
            )

        page_objects = _iter_response_objects(response)
        if response.number_of_objects != len(page_objects):
            self._conflict(
                IdentityConflictCode.OBJECT_COUNT_MISMATCH,
                page,
                f"header declares {response.number_of_objects} objects, "
                f"frame carries {len(page_objects)}",
                fatal=False,
            )

        page_distinct, continuation = self._collect_page_objects(page_objects, page)
        if not continuation:
            self._chain_verified = False

        self._evidence.append(
            _PageEvidence(
                page=page,
                claimed_more_follows=response.more_follows,
                claimed_next_object_id=response.next_object_id,
                claimed_object_count=response.number_of_objects,
                object_count=len(page_objects),
                locally_verified_continuation=continuation,
            )
        )

        if not self._within_byte_bound(page):
            return

        if response.more_follows != MoreData.KEEP_READING:
            self._terminal_claim = True
            self._stop = True
            return

        # The endpoint claims another page. Prove the claim actually advances.
        if not page_distinct:
            self._conflict(
                IdentityConflictCode.NO_PROGRESS,
                page,
                "more follows asserted but the page carried no objects",
            )
            return
        if not continuation:
            # Overlap / non-advancing page means following next_object_id would
            # re-read data the endpoint already sent.
            self._conflict(
                IdentityConflictCode.NO_PROGRESS,
                page,
                "more follows asserted but the page did not advance cleanly",
            )
            return

        self._next_object_id = response.next_object_id

    def _within_byte_bound(self, page: int) -> bool:
        """Record a byte-bound conflict; the bound is checked per whole page."""
        if self._identity_bytes <= self._limits.max_identity_bytes:
            return True
        self._conflict(
            IdentityConflictCode.BYTE_LIMIT_REACHED,
            page,
            f"{self._identity_bytes} identity bytes exceed bound "
            f"{self._limits.max_identity_bytes}",
        )
        return False

    def _build_result(self) -> DeviceIdentityResult:
        complete = (
            self._chain_verified
            and not self._conflicts
            and self._terminal_claim
            and self._pages_requested >= 1
        )
        return DeviceIdentityResult(
            read_code=self._read_code,
            complete=complete,
            pages_requested=self._pages_requested,
            identity_bytes=self._identity_bytes,
            objects=list(self._objects),
            conflicts=list(self._conflicts),
            page_evidence=list(self._evidence),
            claimed_more_follows=self._claimed_more_follows,
            claimed_next_object_id=self._claimed_next_object_id,
        )

    def _next_request(self) -> ModbusPDU:
        return ReadDeviceInformationRequest(
            read_code=self._read_code,
            object_id=self._next_object_id,
            dev_id=self._device_id,
        )

    def _page_limit_hit(self) -> bool:
        if self._pages_requested < self._limits.max_pages:
            return False
        self._conflict(
            IdentityConflictCode.PAGE_LIMIT_REACHED,
            self._pages_requested,
            f"page limit {self._limits.max_pages} reached while more follows",
        )
        return True

    async def run_async(
        self, transport: AsyncIdentityTransport
    ) -> DeviceIdentityResult:
        """Drive the bounded read against an awaitable transport."""
        while not self._stop:
            if self._page_limit_hit():
                break
            response = await transport(self._next_request())
            self._pages_requested += 1
            self._handle_response(response)
        return self._build_result()

    def run_sync(self, transport: SyncIdentityTransport) -> DeviceIdentityResult:
        """Drive the bounded read against a synchronous transport."""
        while not self._stop:
            if self._page_limit_hit():
                break
            response = transport(self._next_request())
            self._pages_requested += 1
            self._handle_response(response)
        return self._build_result()


async def read_device_identity(
    transport: AsyncIdentityTransport,
    *,
    read_code: int = DeviceInformation.BASIC,
    device_id: int = 1,
    limits: IdentityReadLimits | None = None,
) -> DeviceIdentityResult:
    """Read a full device identity behind hard page and byte bounds.

    :param transport: awaitable callable mapping a request PDU to its response,
        typically a bound ``client.execute`` wrapper.
    :param read_code: access level to request (basic/regular/extended/specific).
    :param device_id: Modbus device / unit id.
    :param limits: caller supplied page and byte bounds.
    :returns: a :class:`DeviceIdentityResult`; never raises on protocol abuse.

    The loop is bounded by :class:`IdentityReadLimits`. When a bound is hit the
    returned result keeps the objects collected so far but reports
    ``complete=False`` and a matching conflict, so partial identity data cannot
    be mistaken for a verified device profile.
    """
    bounds = limits or IdentityReadLimits()
    reader = _IdentityReader(int(read_code), device_id, bounds)
    return await reader.run_async(transport)


def read_device_identity_sync(
    transport: SyncIdentityTransport,
    *,
    read_code: int = DeviceInformation.BASIC,
    device_id: int = 1,
    limits: IdentityReadLimits | None = None,
) -> DeviceIdentityResult:
    """Read a full device identity synchronously behind hard bounds.

    The transport must return the response directly instead of a coroutine,
    e.g. a bound synchronous ``client.execute`` wrapper.
    """
    bounds = limits or IdentityReadLimits()
    reader = _IdentityReader(int(read_code), device_id, bounds)
    return reader.run_sync(transport)
