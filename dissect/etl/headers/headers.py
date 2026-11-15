from __future__ import annotations

from abc import abstractmethod
from enum import IntEnum
from io import BytesIO
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.etl.c_etl import c_etl
from dissect.etl.exceptions import InvalidHeaderError, InvalidMarkerError

if TYPE_CHECKING:
    from datetime import datetime

    from dissect.cstruct.types.structure import Structure
    from dissect.etl.etl import ETL


BIT64_HEADERS = [
    c_etl.TRACE_HEADER_TYPE_SYSTEM64,
    c_etl.TRACE_HEADER_TYPE_COMPACT64,
    c_etl.TRACE_HEADER_TYPE_PERFINFO64,
    c_etl.TRACE_HEADER_TYPE_EVENT_HEADER64,
    c_etl.TRACE_HEADER_TYPE_FULL_HEADER64,
    c_etl.TRACE_HEADER_TYPE_INSTANCE64,
]


class Marker:
    """Abstracts the marker calculation for headers."""

    MARKER_MASK = 0xFF000000
    HEADER_MASK = 0x00FF0000
    REMAINDER_MASK = 0x0000FFFF

    MESSAGE_FLAGS = 0x90
    HEADER_FLAGS = 0xC0

    def __init__(self, marker: int):
        self.marker = marker

    @property
    def flags(self) -> int:
        return (self.marker & self.MARKER_MASK) >> 24

    @property
    def header_type(self) -> int:
        if self.flags == self.HEADER_FLAGS:
            return (self.marker & self.HEADER_MASK) >> 16
        if self.flags == self.MESSAGE_FLAGS:
            return c_etl.TRACE_HEADER_TYPE_MESSAGE

        raise InvalidMarkerError("Unknown flags combination")

    @property
    def remainder(self) -> int:
        return self.marker & self.REMAINDER_MASK


class Header:
    """A baseclass for the different ETL headers."""

    def __init__(self, marker: Marker, data: memoryview, etl: ETL):
        self._etl = etl
        self._marker = marker
        self._header = None
        self._payload = None
        self.data = data

        if self.size < self.minimal_size:
            raise InvalidHeaderError(
                f"Size too small for record type 0x{self._marker.header_type:02x}"
                f" from marker 0x{self.marker:08x} ({self.size} < {self.minimal_size}"
            )

    @property
    @abstractmethod
    def minimal_size(self) -> int:
        """Minimum header size."""

    @property
    @abstractmethod
    def _header_type(self) -> type[Structure] | None:
        """Type of header that will get parsed."""

    @property
    def provider_id(self) -> UUID:
        """Provider that generated this event."""
        return UUID(bytes_le=self.header.ProviderId)

    @property
    def version(self) -> int:
        """The version of the event."""
        return self.header.Version

    @property
    def timestamp(self) -> datetime:
        """The timestamp of the event."""
        return self._etl.calculate_timestamp(self.time_delta)

    @property
    def time_delta(self) -> int:
        """The change in time relative to the start of the logfile."""
        return self.header.TimeDelta

    @property
    def marker(self) -> int:
        """The marker data for this event."""
        return self._marker.marker

    @property
    def is_64bit(self) -> bool:
        """A value to determine if the header is 64 or 32 bits."""
        return self._marker.header_type in BIT64_HEADERS

    @property
    def size(self) -> int:
        """The size of the event.

        In most cases this is inside the remainder field of the marker.
        """
        return self._marker.remainder

    @property
    def data_size(self) -> int:
        """The size of the payload."""
        return self.size - self.minimal_size

    @property
    def payload(self) -> memoryview:
        """Grab the payload data from the datastream."""
        if not self._payload:
            self._payload = self.data[self.minimal_size : self.size]
        return self._payload

    @property
    def header(self) -> Structure:
        """Type of header that will get parsed."""
        if not self._header:
            self._header = self._header_type(self.data[: self.minimal_size])
        return self._header

    @abstractmethod
    def additional_header_fields(self) -> dict[str, Any]:
        """Additional fields that hold interesting information.

        each header subclass defines what additional information it wants to return to a record.
        """

    def standard_header_fields(self) -> dict[str, Any]:
        """Some standard header information that can be retrieved for any header."""
        return {
            "version": self.version,
            "provider_id": self.provider_id,
            "timestamp": self.timestamp,
        }

    def __repr__(self) -> str:
        standard_output = " ".join(f"{key}={value}" for key, value in self.standard_header_fields().items())
        additional_output = " ".join(f"{key}={value}" for key, value in self.additional_header_fields().items())
        return f"<{self.__class__.__name__} {standard_output} {additional_output}>"


class InvalidHeader(Header):
    """An invalid header."""

    def __init__(self, marker: Marker, data: bytes, etl: ETL):
        raise InvalidHeaderError


class UnimplementedHeader(Header):
    """A header that isn't implemented yet."""


class EventProperty(IntEnum):
    """Defines what the message trace header can additionally find in its payload.

    The order of the members below mirrors the order in which the optional fields
    are laid out inside the record payload. ``POINTER32`` and ``POINTER64`` do not
    consume any bytes themselves; they only describe the pointer width used inside
    the (WPP) message bytes.
    """

    SEQUENCE = 0x0001
    GUID = 0x0002
    COMPONENT_ID = 0x0004
    TIMESTAMP = 0x0008
    PERFORMANCE_TIMESTAMP = 0x0010
    SYSTEMINFO = 0x0020
    POINTER32 = 0x0040
    POINTER64 = 0x0080


# Size in bytes of every optional field that consumes payload bytes.
# The pointer width flags deliberately have no entry as they carry no data.
_MESSAGE_FIELD_SIZES = {
    EventProperty.SEQUENCE: 4,
    EventProperty.GUID: 16,
    EventProperty.COMPONENT_ID: 2,
    EventProperty.TIMESTAMP: 8,
    EventProperty.SYSTEMINFO: 8,
}

# Order in which the optional, byte-carrying fields appear inside the payload.
_MESSAGE_FIELD_ORDER = (
    EventProperty.SEQUENCE,
    EventProperty.GUID,
    EventProperty.COMPONENT_ID,
    EventProperty.TIMESTAMP,
    EventProperty.SYSTEMINFO,
)

# Flags that do not carry payload bytes but describe how to interpret the message.
_MESSAGE_POINTER_FLAGS = EventProperty.POINTER32 | EventProperty.POINTER64
_MESSAGE_KNOWN_FLAGS = (
    EventProperty.SEQUENCE
    | EventProperty.GUID
    | EventProperty.COMPONENT_ID
    | EventProperty.TIMESTAMP
    | EventProperty.PERFORMANCE_TIMESTAMP
    | EventProperty.SYSTEMINFO
    | EventProperty.POINTER32
    | EventProperty.POINTER64
)


class MessageTraceHeader(Header):
    """A WPP message trace record (``TRACE_HEADER_TYPE_MESSAGE``).

    The fixed 8 byte :class:`MessageHeader` is followed by a set of optional fields
    whose presence is declared by the :attr:`EventProperty` bitmask. After those
    optional fields come the actual WPP message bytes.

    Fields are only interpreted when their property bit is set and each is read from
    its own position, so GUID, component id, sequence number, timestamp and system
    information can never displace each other. When a declared field cannot be fully
    read because the record is truncated, parsing stops, the missing part is recorded
    in :attr:`warnings` together with the unconsumed bytes, and no further values are
    fabricated.
    """

    def __init__(self, marker: Marker, data: bytes, etl: ETL):
        super().__init__(marker, data, etl)
        self.opcode = None
        self._thread_id = None
        self._process_id = None
        self._sequence_number = None
        self._component_id = None
        self._provider_id = None
        self._time_delta = None
        self._has_timestamp = False
        self._pointer_size = None
        self._identity_ambiguous = False
        self.warnings: list[str] = []
        self._parse_event_properties()

    @property
    def minimal_size(self) -> int:
        return 0x8

    @property
    def _header_type(self) -> type[c_etl.MessageHeader]:
        return c_etl.MessageHeader

    def _parse_event_properties(self) -> None:
        stream = BytesIO(self._optional_region())

        self._validate_property_combinations()

        for field in _MESSAGE_FIELD_ORDER:
            if not self.event_property & field:
                continue
            if (
                field in (EventProperty.GUID, EventProperty.COMPONENT_ID)
                and self._identity_ambiguous
            ):
                # GUID and component id claim the same slot; never guess which one the
                # bytes represent. The slot is still consumed exactly once (for GUID)
                # so following fields keep their positions.
                if field == EventProperty.GUID:
                    self._skip_field(stream, field)
                continue
            if not self._read_field(stream, field):
                # The record is truncated inside this field. Stop interpreting any
                # later field; its bytes are part of the same truncated region.
                break

        self._message_offset = self.minimal_size + stream.tell()

    def _optional_region(self) -> bytes:
        # Everything between the fixed header and the declared record size is either
        # an optional field or the WPP message. Reading beyond the declared size must
        # never happen, so cap the region on the (possibly truncated) available data.
        end = min(self.size, len(self.data))
        if end < self.minimal_size:
            return b""
        return bytes(self.data[self.minimal_size : end])

    def _read_field(self, stream: BytesIO, field: EventProperty) -> bool:
        size = _MESSAGE_FIELD_SIZES[field]
        raw = stream.read(size)
        if len(raw) < size:
            self._record_truncation(stream, field, raw)
            return False
        if field == EventProperty.SEQUENCE:
            self._sequence_number = c_etl.uint32(raw)
        elif field == EventProperty.GUID:
            self._provider_id = UUID(bytes_le=raw)
        elif field == EventProperty.COMPONENT_ID:
            self._component_id = c_etl.uint16(raw)
        elif field == EventProperty.TIMESTAMP:
            self._time_delta = c_etl.uint64(raw)
            self._has_timestamp = True
        elif field == EventProperty.SYSTEMINFO:
            self._thread_id = c_etl.uint32(raw[:4])
            self._process_id = c_etl.uint32(raw[4:])
        return True

    def _skip_field(self, stream: BytesIO, field: EventProperty) -> bool:
        raw = stream.read(_MESSAGE_FIELD_SIZES[field])
        if len(raw) < _MESSAGE_FIELD_SIZES[field]:
            self._record_truncation(stream, field, raw)
            return False
        return True

    def _record_truncation(
        self, stream: BytesIO, field: EventProperty, raw: bytes
    ) -> None:
        expected = _MESSAGE_FIELD_SIZES[field]
        self.warnings.append(
            f"Truncated WPP record: missing {expected - len(raw)} of {expected} byte(s) "
            f"of the {field.name} field; {len(raw)} partial byte(s) left uninterpreted"
        )
        if raw:
            self.warnings.append(f"Partial {field.name} bytes retained: 0x{raw.hex()}")

    def _validate_property_combinations(self) -> None:
        # GUID and component id occupy the same slot and are mutually exclusive.
        identity = self.event_property & (
            EventProperty.GUID | EventProperty.COMPONENT_ID
        )
        if identity == (EventProperty.GUID | EventProperty.COMPONENT_ID):
            self._identity_ambiguous = True
            self.warnings.append(
                "EventProperty sets both GUID and COMPONENT_ID which share the same payload slot; "
                "the combination is ambiguous, no provider identity was interpreted"
            )

        # The two pointer widths are mutually exclusive. They carry no bytes but tell
        # how pointers inside the WPP message must be read.
        pointer_flags = self.event_property & _MESSAGE_POINTER_FLAGS
        if pointer_flags == _MESSAGE_POINTER_FLAGS:
            self.warnings.append(
                "EventProperty sets both POINTER32 and POINTER64; pointer width is ambiguous, "
                "raw pointer bytes are left uninterpreted"
            )
        elif pointer_flags == EventProperty.POINTER32:
            self._pointer_size = 4
        elif pointer_flags == EventProperty.POINTER64:
            self._pointer_size = 8

        unknown = self.event_property & ~_MESSAGE_KNOWN_FLAGS
        if unknown:
            self.warnings.append(
                f"EventProperty contains unknown flag(s) 0x{unknown:04x}; they carry no supported "
                "interpretation and are retained in the raw property value"
            )
        if self.event_property & EventProperty.PERFORMANCE_TIMESTAMP:
            self.warnings.append(
                "PERFORMANCE_TIMESTAMP is declared but its placement is not standardized for WPP "
                "message records; no timestamp was derived from it"
            )

    @property
    def time_delta(self) -> int | None:
        return self._time_delta

    @property
    def timestamp(self) -> datetime | None:
        """The timestamp of the event.

        Returns ``None`` when the record does not carry a timestamp instead of
        turning the missing time into the logfile start time.
        """
        if not self._has_timestamp:
            return None
        return self._etl.calculate_timestamp(self._time_delta)

    @property
    def version(self) -> int:
        return None

    @property
    def id(self) -> int:
        """The id of the message event."""
        return self.header.Id

    @property
    def event_property(self) -> int:
        """What type of payload to expect."""
        return self.header.EventProperty

    @property
    def provider_id(self) -> UUID | None:
        return self._provider_id

    @property
    def component_id(self) -> int | None:
        return self._component_id

    @property
    def thread_id(self) -> int | None:
        return self._thread_id

    @property
    def process_id(self) -> int | None:
        return self._process_id

    @property
    def sequence_number(self) -> int | None:
        return self._sequence_number

    @property
    def pointer_size(self) -> int | None:
        """Pointer width (4 or 8) declared by the record, if any."""
        return self._pointer_size

    @property
    def message(self) -> memoryview:
        """The raw WPP message bytes that follow the optional header fields."""
        return self.data[self._message_offset : self.size]

    @property
    def payload(self) -> memoryview:
        # For WPP records the meaningful payload is the WPP message itself, not the
        # optional header fields. Keep message start/end marker bytes intact here.
        return self.message

    def standard_header_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "provider_id": self.provider_id,
            "timestamp": self.timestamp,
        }

    def additional_header_fields(self) -> dict[str, Any]:
        return {
            "Id": self.id,
            "EventProperty": f"0x{self.event_property:04x}",
            "SequenceNumber": self.sequence_number,
            "ComponentId": self.component_id,
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
            "PointerSize": self.pointer_size,
            "Message": bytes(self.message),
            "Warnings": list(self.warnings),
        }


class EventTraceHeader(Header):
    @property
    def minimal_size(self) -> int:
        return 0x30

    @property
    def _header_type(self) -> type[c_etl.EventTraceHeader]:
        return c_etl.EventTraceHeader

    @property
    def thread_id(self) -> int:
        """The thread id that created this event."""
        return self.header.ThreadId

    @property
    def process_id(self) -> int:
        """The process id that created this event."""
        return self.header.ProcessId

    def additional_header_fields(self) -> dict[str, Any]:
        return {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
        }


class EventInstanceHeader(Header):
    @property
    def minimal_size(self) -> int:
        return 0x38

    @property
    def _header_type(self) -> type[c_etl.EventInstanceHeader]:
        return c_etl.EventInstanceHeader

    def additional_header_fields(self) -> dict[str, Any]:
        return {
            "ThreadId": self.header.ids.information.ThreadId,
            "ProcessId": self.header.ids.information.ProcessId,
        }


class EventInstanceGUIDHeader(Header):
    """A more expanded EventInstanceHeader.

    This is created from an EventInstanceHeader, but it's not quite clear which one is specifically used.
    For now, this header is default.
    """

    @property
    def minimal_size(self) -> int:
        return 0x48

    @property
    def _header_type(self) -> type[c_etl.EventInstanceGUIDHeader]:
        return c_etl.EventInstanceGUIDHeader

    @property
    def thread_id(self) -> int:
        """The thread id that created this event."""
        return self.header.ThreadId

    @property
    def process_id(self) -> int:
        """The process id that created this event."""
        return self.header.ProcessId

    @property
    def parent_guid(self) -> int:
        return UUID(bytes_le=self.header.ParentGuid)

    def additional_header_fields(self) -> dict[str, Any]:
        return {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
            "ParentGuid": f"{self.parent_guid}",
        }


class ErrorHeader(Header):
    """When an error event was created. However, the structure of the header isn't clear."""

    @property
    def minimal_size(self) -> int:
        return 0x50

    @property
    def _header_type(self) -> None:
        return None

    def additional_header_fields(self) -> dict[str, Any]:
        return {}
