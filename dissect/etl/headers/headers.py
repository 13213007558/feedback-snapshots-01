from __future__ import annotations

from abc import abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.util.ts import wintimestamp

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

    The values are the ``TRACE_MESSAGE_*`` flags passed to ``TraceMessage``. Flags
    control which values are appended, in a fixed order, between the 8 byte
    ``MESSAGE_HEADER`` and the actual WPP message::

        sequence number (4) -> GUID (16) -> component id (2) -> timestamp (8)
        -> performance timestamp (8) -> system information (8)

    The optional header is a packed byte stream: values follow each other without
    alignment padding, because ``TraceMessage`` writes them sequentially.

    ``POINTER32`` and ``POINTER64`` only select the pointer size used to format
    message arguments; they do not add bytes to the optional header.
    """

    SEQUENCE = 0x0001
    GUID = 0x0002
    COMPONENT_ID = 0x0004
    TIMESTAMP = 0x0008
    PERFORMANCE_TIMESTAMP = 0x0010
    SYSTEMINFO = 0x0020
    POINTER32 = 0x0040
    POINTER64 = 0x0080


# (flag, attribute name, size) in the order the values are appended to the record.
# This order is part of the record layout: changing it would make one declared
# property consume the bytes of another one.
MESSAGE_PROPERTY_LAYOUT: tuple[tuple[EventProperty, str, int], ...] = (
    (EventProperty.SEQUENCE, "sequence_number", 4),
    (EventProperty.GUID, "provider_id", 16),
    (EventProperty.COMPONENT_ID, "component_id", 2),
    (EventProperty.TIMESTAMP, "timestamp_filetime", 8),
    (EventProperty.PERFORMANCE_TIMESTAMP, "performance_timestamp", 8),
    (EventProperty.SYSTEMINFO, "system_info", 8),
)

KNOWN_MESSAGE_PROPERTIES = 0x00FF


class MessageTraceHeader(Header):
    """A WPP ``MessageTrace`` record.

    The record starts with an 8 byte ``MESSAGE_HEADER`` (size, marker, id and
    event property). Everything after it is the optional header selected by the
    event property, followed by the real message bytes.

    Optional values are read strictly in the order declared in
    :data:`MESSAGE_PROPERTY_LAYOUT`. A property that is declared but does not
    fit inside the record is not padded or guessed: parsing stops, the affected
    field names are recorded in :attr:`truncated_fields` and
    :attr:`truncation`, and no message offset is reported.

    Time handling is intentionally conservative. ``TRACE_MESSAGE_TIMESTAMP``
    carries an absolute FILETIME (100ns since 1601-01-01), not a delta from the
    log start, so it is converted directly. If the flag is absent,
    :attr:`timestamp` and :attr:`time_delta` are ``None``; they are never
    replaced with the logfile start time.
    """

    def __init__(self, marker: Marker, data: bytes, etl: ETL):
        self.payload_offset = 0
        self.opcode = None
        self._thread_id: int | None = None
        self._process_id: int | None = None
        self._system_info: bytes | None = None
        self._sequence_number: int | None = None
        self._provider_id: UUID | None = None
        self._component_id: int | None = None
        self._timestamp_filetime: int | None = None
        self._timestamp: datetime | None = None
        self._performance_timestamp: int | None = None
        self._message_offset: int | None = None
        self._message: bytes | None = None
        self._optional_header = b""
        self._truncated_fields: tuple[str, ...] = ()
        self._truncation: str | None = None
        self._record_truncated = False
        self._limitations: list[str] = []

        super().__init__(marker, data, etl)

        self._parse_event_properties()

    @property
    def minimal_size(self) -> int:
        return 0x8

    @property
    def _header_type(self) -> type[c_etl.MessageHeader]:
        return c_etl.MessageHeader

    def _parse_event_properties(self) -> None:
        declared = [(name, size) for flag, name, size in MESSAGE_PROPERTY_LAYOUT if self.event_property & flag]

        # Header.data is the rest of the buffer from the record offset. If the
        # record's own declared size exceeds it, the record is cut off; parse the
        # fields that are still present but never trust a message boundary.
        self._record_truncated = len(self.data) < self.size
        if self._record_truncated:
            self._add_limitation(
                f"record truncated: declared size {self.size} but only {len(self.data)} bytes available"
            )

        payload_end = min(self.size, len(self.data))
        payload = self.data[self.minimal_size : payload_end]
        offset = 0
        values: dict[str, int | bytes | UUID] = {}

        for index, (name, size) in enumerate(declared):
            available = len(payload) - offset
            if available < size:
                self._truncated_fields = tuple(field_name for field_name, _ in declared[index:])
                prefix = "record truncated" if self._record_truncated else "optional header truncated"
                self._truncation = (
                    f"{prefix} at record offset {self.minimal_size + offset}: "
                    f"{name} requires {size} bytes, only {available} available"
                )
                if len(self._truncated_fields) > 1:
                    self._truncation += f" (also missing: {', '.join(self._truncated_fields[1:])})"
                self._add_limitation("optional message header is incomplete; message bytes cannot be located")
                # Keep the values that did fit, so the partial evidence is not
                # thrown away, but never report a message boundary.
                self._apply_optional_values(values)
                self._optional_header = bytes(payload[:offset])
                self._check_property_combination()
                return

            raw = payload[offset : offset + size]
            offset += size

            if name == "provider_id":
                values[name] = UUID(bytes_le=bytes(raw))
            elif name == "system_info":
                # TRACE_MESSAGE_SYSTEMINFO appends the process id and then the
                # thread id. The raw bytes stay available as ``system_info`` so a
                # caller can re-check the pair against the source.
                process_id, thread_id = c_etl.uint32[2](raw)
                values["process_id"] = process_id
                values["thread_id"] = thread_id
                values["system_info"] = bytes(raw)
            else:
                values[name] = c_etl.uint64(raw) if size == 8 else c_etl.uint32(raw) if size == 4 else c_etl.uint16(raw)

        self._apply_optional_values(values)
        self._optional_header = bytes(payload[:offset])

        if not self._record_truncated:
            self._message_offset = self.minimal_size + offset
            self._message = bytes(self.data[self._message_offset : self.size])
        elif not self._truncation:
            # All declared optional fields are present, but the message tail is
            # missing because the record itself is cut off.
            self._truncation = (
                f"record truncated: declared size {self.size} but only {len(self.data)} bytes available; "
                "message bytes cannot be located"
            )

        self._check_property_combination()

    def _apply_optional_values(self, values: dict[str, int | bytes | UUID]) -> None:
        self._sequence_number = values.get("sequence_number")
        self._provider_id = values.get("provider_id")
        self._component_id = values.get("component_id")
        self._performance_timestamp = values.get("performance_timestamp")
        self._thread_id = values.get("thread_id")
        self._process_id = values.get("process_id")
        self._system_info = values.get("system_info")

        if "timestamp_filetime" in values:
            self._timestamp_filetime = values["timestamp_filetime"]
            self._timestamp = self._convert_timestamp(self._timestamp_filetime)

        if "performance_timestamp" in values:
            self._add_limitation(
                "performance_timestamp is a performance counter value, not wall clock; "
                "it is not converted to a timestamp"
            )

    def _convert_timestamp(self, filetime: int) -> datetime | None:
        try:
            return wintimestamp(filetime)
        except (OverflowError, OSError, ValueError):
            self._add_limitation(f"timestamp value 0x{filetime:x} is not a representable FILETIME")
            return None

    def _check_property_combination(self) -> None:
        if self.event_property & EventProperty.TIMESTAMP and self.event_property & EventProperty.PERFORMANCE_TIMESTAMP:
            self._add_limitation(
                "TRACE_MESSAGE_TIMESTAMP and TRACE_MESSAGE_PERFORMANCE_TIMESTAMP are both set; "
                "both raw 64 bit values are preserved"
            )

        pointer32 = bool(self.event_property & EventProperty.POINTER32)
        pointer64 = bool(self.event_property & EventProperty.POINTER64)
        if pointer32 and pointer64:
            self._add_limitation(
                "conflicting pointer flags POINTER32 and POINTER64 are both set; "
                "the pointer size for message arguments is ambiguous"
            )
        elif pointer32 or pointer64:
            self._add_limitation(
                f"{'POINTER32' if pointer32 else 'POINTER64'} only affects argument formatting; "
                "message bytes are returned unmodified"
            )

        unknown = self.event_property & ~KNOWN_MESSAGE_PROPERTIES
        if unknown:
            self._add_limitation(f"unknown message property bits 0x{unknown:04x} are preserved but not interpreted")

    def _add_limitation(self, limitation: str) -> None:
        if limitation not in self._limitations:
            self._limitations.append(limitation)

    @property
    def time_delta(self) -> None:
        """Always ``None``.

        A message trace record has no log-relative clock delta. Returning the
        absolute FILETIME here would let callers feed it to
        :meth:`ETL.calculate_timestamp` and fabricate a timestamp from the
        logfile start. Use :attr:`timestamp_filetime` for the raw value.
        """
        return None

    @property
    def timestamp_filetime(self) -> int | None:
        """The raw 100ns FILETIME value carried by the record, or ``None``."""
        return self._timestamp_filetime

    @property
    def timestamp(self) -> datetime | None:
        """The event timestamp, or ``None`` when the record carries no timestamp.

        A missing timestamp is never replaced by the start of the logfile.
        """
        return self._timestamp

    @property
    def performance_timestamp(self) -> int | None:
        """The raw performance counter value, when declared."""
        return self._performance_timestamp

    @property
    def version(self) -> None:
        return None

    @property
    def id(self) -> int:
        """The id of the message event."""
        return self.header.Id

    @property
    def event_property(self) -> int:
        """The raw ``EventProperty`` flags of the record."""
        return self.header.EventProperty

    @property
    def property_names(self) -> tuple[str, ...]:
        """Names of the known properties declared by the record."""
        return tuple(name for flag, name, _ in MESSAGE_PROPERTY_LAYOUT if self.event_property & flag)

    @property
    def provider_id(self) -> UUID | None:
        """The message GUID, when the record declares ``TRACE_MESSAGE_GUID``."""
        return self._provider_id

    @property
    def guid(self) -> UUID | None:
        """Alias for :attr:`provider_id`."""
        return self._provider_id

    @property
    def component_id(self) -> int | None:
        """The 16 bit WPP component id, when the record declares it.

        ``TRACE_MESSAGE_COMPONENTID`` carries a ``USHORT`` component number, not a
        second GUID.
        """
        return self._component_id

    @property
    def system_info(self) -> bytes | None:
        """The raw 8 byte system information value, when declared."""
        return self._system_info

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
    def optional_header(self) -> bytes:
        """The raw optional header bytes that precede the message.

        Empty when the record is truncated. This allows every parsed value to be
        re-checked against the original bytes.
        """
        return self._optional_header

    @property
    def message_offset(self) -> int | None:
        """Offset of the message bytes from the start of the record.

        ``None`` when a declared optional property is truncated, because the
        start of the message cannot be established in that case.
        """
        return self._message_offset

    @property
    def message(self) -> bytes:
        """The real message bytes after the optional header.

        The bytes are returned verbatim, including leading and trailing bytes
        that look like a record marker. Empty when the optional header is
        truncated.
        """
        if self._message is None:
            return b""
        return self._message

    @property
    def message_size(self) -> int:
        return len(self.message)

    @property
    def payload(self) -> memoryview:
        """The record payload after the optional header, i.e. the message bytes.

        This differs from the base class, where the payload starts right after a
        fixed size header. For a message trace record the optional header is part
        of the header, so the payload must start at :attr:`message_offset`.
        """
        if self._message_offset is None:
            return memoryview(b"")
        return self.data[self._message_offset : self.size]

    @property
    def data_size(self) -> int:
        """The size of the message bytes, excluding the optional header."""
        return self.message_size

    @property
    def truncated_fields(self) -> tuple[str, ...]:
        """Names of the declared properties that do not fit in the record."""
        return self._truncated_fields

    @property
    def truncation(self) -> str | None:
        """A description of which property is incomplete, or ``None``."""
        return self._truncation

    @property
    def record_truncated(self) -> bool:
        """``True`` when the record ends before its own declared size."""
        return self._record_truncated

    @property
    def limitations(self) -> tuple[str, ...]:
        """Raw values or combinations that are preserved but not interpreted."""
        return tuple(self._limitations)

    @property
    def pointer_size(self) -> int | None:
        """The pointer size selected by the pointer flags, or ``None``."""
        if self.event_property & EventProperty.POINTER32 and self.event_property & EventProperty.POINTER64:
            return None
        if self.event_property & EventProperty.POINTER32:
            return 4
        if self.event_property & EventProperty.POINTER64:
            return 8
        return None

    def additional_header_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
            "SequenceNumber": self.sequence_number,
            "ComponentId": self.component_id,
            "MessageOffset": self.message_offset,
        }
        if self.truncated_fields:
            fields["TruncatedFields"] = list(self.truncated_fields)
        if self.limitations:
            fields["Limitations"] = list(self.limitations)
        return fields


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
