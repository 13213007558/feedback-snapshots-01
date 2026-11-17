"""
Backup review service adapter
=============================

A scoped implementation of the BACnet AtomicReadFile and AtomicWriteFile
services (ASHRAE 135 clauses 15.6 / 15.7) built directly on the BACpypes3
APDU structures.  It models a *backup review* interface that is only allowed
to read an explicitly approved range of a BACnet File object.

Design goals
------------

* The authorization context binds three things together and never lets them
  drift: the File object identifier, the single permitted access mode
  ("streamAccess" or "recordAccess") and the readable half-open window
  ``[range_start, range_end)``.
* Record access and byte (stream) access are two distinct address spaces.
  A record count is never sliced out of a byte string and a byte offset is
  never used as a record index -- :class:`StreamBackupFile` and
  :class:`RecordBackupFile` keep the two shapes separate.
* Every negative outcome maps to its protocol result: an
  :class:`~bacpypes3.errors.ExecutionError` becomes an Error PDU, a
  :class:`~bacpypes3.errors.RejectException` becomes a Reject PDU.
* Writes are denied unless a policy explicitly grants them; switching the
  access mode on the request can never widen the approved window.

The mixin is transport independent: it only calls ``self.response`` and
``self.get_object_id``, both provided by :class:`bacpypes3.app.Application`,
so it can be driven off-network in tests or wired into a live stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from bacpypes3.apdu import (
    AtomicReadFileACK,
    AtomicReadFileRequest,
    AtomicWriteFileACK,
    AtomicWriteFileRequest,
)
from bacpypes3.basetypes import (
    AtomicReadFileACKAccessMethodChoice,
    AtomicReadFileACKAccessMethodRecordAccess,
    AtomicReadFileACKAccessMethodStreamAccess,
    AtomicReadFileRequestAccessMethodChoice,
    AtomicWriteFileRequestAccessMethodChoice,
)
from bacpypes3.constructeddata import SequenceOf
from bacpypes3.debugging import ModuleLogger, bacpypes_debugging
from bacpypes3.errors import (
    ExecutionError,
    InconsistentParameters,
    MissingRequiredParameter,
)
from bacpypes3.primitivedata import (
    Boolean,
    Integer,
    ObjectIdentifier,
    OctetString,
    Unsigned,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())

#: access method selector names, matching the Choice member names
STREAM_ACCESS = "streamAccess"
RECORD_ACCESS = "recordAccess"
_ACCESS_METHODS = (STREAM_ACCESS, RECORD_ACCESS)

#: SequenceOf OctetString, the type of AtomicReadFileACK fileRecordData
SequenceOfOctetString = SequenceOf(OctetString)


def _service_error(error_code: str) -> ExecutionError:
    """Build a services-class Error PDU source for a protocol error code."""
    return ExecutionError(errorClass="services", errorCode=error_code)


#
#   In-memory files
#


@dataclass
class StreamBackupFile:
    """A byte-oriented file addressed by octet position.

    The payload is a single ``bytes`` buffer; every position means an octet
    offset.  Nothing here interprets the content as records.
    """

    file_identifier: ObjectIdentifier
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    def read_window(self, start: int, end: int) -> Tuple[bytes, int, bool]:
        """Return ``(data, start_position, end_of_file)`` for an octet range."""
        window = self.data[start:end]
        return window, start, (start + len(window)) >= self.size

    def write(self, start: int, payload: bytes) -> int:
        """Overwrite bytes at ``start``; the review file never grows."""
        if start < 0 or start > self.size:
            raise _service_error("invalidFileStartPosition")
        if start + len(payload) > self.size:
            raise _service_error("fileFull")
        self.data = self.data[:start] + payload + self.data[start + len(payload) :]
        return start


@dataclass
class RecordBackupFile:
    """A record-oriented file addressed by record index.

    Each record is a separate :class:`OctetString`; positions index whole
    records, never individual octets.
    """

    file_identifier: ObjectIdentifier
    records: List[OctetString]

    @property
    def record_count(self) -> int:
        return len(self.records)

    def read_window(self, start: int, end: int) -> Tuple[List[OctetString], int, bool]:
        """Return ``(records, start_record, end_of_file)`` by record index."""
        window = self.records[start:end]
        return window, start, (start + len(window)) >= self.record_count

    def write(self, start: int, records: List[OctetString]) -> int:
        """Overwrite whole records at ``start``; the file never grows."""
        if start < 0 or start > self.record_count:
            raise _service_error("invalidFileStartPosition")
        if start + len(records) > self.record_count:
            raise _service_error("fileFull")
        for offset, record in enumerate(records):
            self.records[start + offset] = record
        return start


#
#   Authorization context
#


@dataclass
class ReadGrant:
    """The approved read window for one File object.

    ``range_start``/``range_end`` are half-open.  Their unit depends on
    ``access_method``: octets for stream access, record indices for record
    access.  A grant only authorizes its own access method, so a request
    naming the other method cannot reuse this window.
    """

    file_identifier: ObjectIdentifier
    access_method: str
    range_start: int
    range_end: int

    def covers(self, start: int, end: int) -> bool:
        """True if the half-open ``[start, end)`` is inside the window."""
        return self.range_start <= start and end <= self.range_end and start <= end


@dataclass
class WriteGrant:
    """A half-open window that explicit write policy permits."""

    range_start: int
    range_end: int

    def covers(self, start: int, end: int) -> bool:
        return self.range_start <= start and end <= self.range_end and start <= end


@dataclass
class WritePolicy:
    """Explicit write policy; the default decision for every write is deny."""

    allowed: Dict[Tuple[ObjectIdentifier, str], WriteGrant] = field(
        default_factory=dict
    )

    def permits(
        self,
        file_identifier: ObjectIdentifier,
        access_method: str,
        start: int,
        end: int,
        grant: Optional[ReadGrant],
    ) -> bool:
        write_grant = self.allowed.get((file_identifier, access_method))
        if write_grant is None:
            return False
        # writes may only use the same fixed mode as the read grant
        if grant is None or grant.access_method != access_method:
            return False
        return grant.covers(start, end) and write_grant.covers(start, end)


#
#   Service mixin
#


@bacpypes_debugging
class AtomicFileServices:
    """Application mixin serving scoped Atomic Read/Write File requests."""

    _debug: Callable[..., None]

    #: file identifier -> in-memory file (StreamBackupFile/RecordBackupFile)
    backup_files: Dict[ObjectIdentifier, object]
    #: file identifier -> ReadGrant
    read_grants: Dict[ObjectIdentifier, ReadGrant]
    write_policy: WritePolicy

    def init_atomic_file_services(self) -> None:
        """Initialise the adapter tables; call from the application __init__."""
        self.backup_files = {}
        self.read_grants = {}
        self.write_policy = WritePolicy()

    # -- helpers ---------------------------------------------------------

    def _select_method(self, choice) -> str:
        """Return the named access method or reject an empty/unknown one."""
        method = choice._choice if choice is not None else None
        if method not in _ACCESS_METHODS:
            # missing or unsupported access method is a malformed request
            raise MissingRequiredParameter("access method required")
        return method

    def _authorize_read(
        self,
        file_identifier: ObjectIdentifier,
        method: str,
        start: int,
        requested_count: int,
    ) -> Tuple[ReadGrant, int, int]:
        """Validate object, mode and window; return grant plus safe bounds."""
        if file_identifier not in self.backup_files:
            raise ExecutionError(errorClass="object", errorCode="unknownObject")

        grant = self.read_grants.get(file_identifier)
        if grant is None:
            raise _service_error("fileAccessDenied")

        # the access mode is fixed by the grant; a request cannot switch mode
        # to reach data outside the approved window
        if method != grant.access_method:
            raise _service_error("invalidFileAccessMethod")

        # a negative start is an invalid-file-start-position service error
        if start < 0:
            raise _service_error("invalidFileStartPosition")

        end = start + requested_count
        if not grant.covers(start, end):
            # a start at/beyond the window end cannot name any approved cell
            if start >= grant.range_end:
                raise _service_error("invalidFileStartPosition")
            # intersect the request with the window so a reply never leaks
            # octets/records before the lower bound or past the upper bound
            start = max(start, grant.range_start)
            end = min(end, grant.range_end)

        return grant, start, end

    # -- AtomicReadFile --------------------------------------------------

    async def do_AtomicReadFileRequest(self, apdu: AtomicReadFileRequest) -> None:
        if _debug:
            AtomicFileServices._debug("do_AtomicReadFileRequest %r", apdu)

        file_identifier = apdu.fileIdentifier
        method = self._select_method(apdu.accessMethod)
        method_choice = getattr(apdu.accessMethod, method)

        if method == STREAM_ACCESS:
            start = int(method_choice.fileStartPosition)
            requested = int(method_choice.requestedOctetCount)
        else:
            start = int(method_choice.fileStartRecord)
            requested = int(method_choice.requestedRecordCount)

        _grant, start, end = self._authorize_read(
            file_identifier, method, start, requested
        )
        backup_file = self.backup_files[file_identifier]

        if method == STREAM_ACCESS:
            data, start_position, eof = backup_file.read_window(start, end)
            access = AtomicReadFileACKAccessMethodChoice(
                streamAccess=AtomicReadFileACKAccessMethodStreamAccess(
                    fileStartPosition=Integer(start_position),
                    fileData=OctetString(data),
                )
            )
        else:
            records, start_record, eof = backup_file.read_window(start, end)
            access = AtomicReadFileACKAccessMethodChoice(
                recordAccess=AtomicReadFileACKAccessMethodRecordAccess(
                    fileStartRecord=Integer(start_record),
                    returnedRecordCount=Unsigned(len(records)),
                    fileRecordData=SequenceOfOctetString(records),
                )
            )

        response = AtomicReadFileACK(
            endOfFile=Boolean(eof),
            accessMethod=access,
            context=apdu,
        )
        await self.response(response)

    # -- AtomicWriteFile -------------------------------------------------

    async def do_AtomicWriteFileRequest(self, apdu: AtomicWriteFileRequest) -> None:
        if _debug:
            AtomicFileServices._debug("do_AtomicWriteFileRequest %r", apdu)

        file_identifier = apdu.fileIdentifier
        method = self._select_method(apdu.accessMethod)
        method_choice = getattr(apdu.accessMethod, method)

        if file_identifier not in self.backup_files:
            raise ExecutionError(errorClass="object", errorCode="unknownObject")
        backup_file = self.backup_files[file_identifier]
        grant = self.read_grants.get(file_identifier)

        if method == STREAM_ACCESS:
            start = int(method_choice.fileStartPosition)
            payload = bytes(method_choice.fileData)
            end = start + len(payload)
        else:
            start = int(method_choice.fileStartRecord)
            records = list(method_choice.fileRecordData)
            if int(method_choice.recordCount) != len(records):
                raise InconsistentParameters("recordCount mismatch")
            end = start + len(records)

        # writes follow the explicit policy; default is deny, and a mode
        # switch cannot enlarge the approved window
        if not self.write_policy.permits(file_identifier, method, start, end, grant):
            raise _service_error("writeAccessDenied")

        if method == STREAM_ACCESS:
            start_position = backup_file.write(start, payload)
            response = AtomicWriteFileACK(
                fileStartPosition=Integer(start_position),
                context=apdu,
            )
        else:
            start_record = backup_file.write(start, records)
            response = AtomicWriteFileACK(
                fileStartRecord=Integer(start_record),
                context=apdu,
            )

        await self.response(response)


__all__ = [
    "STREAM_ACCESS",
    "RECORD_ACCESS",
    "SequenceOfOctetString",
    "StreamBackupFile",
    "RecordBackupFile",
    "ReadGrant",
    "WriteGrant",
    "WritePolicy",
    "AtomicFileServices",
    "AtomicReadFileRequestAccessMethodChoice",
    "AtomicWriteFileRequestAccessMethodChoice",
]
