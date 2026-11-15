"""Offline construction of minimal, self-contained ETL files.

The generated file mirrors the on-disk layout that :class:`dissect.etl.etl.ETL` expects:

* one :class:`~dissect.etl.c_etl.c_etl.BufferHeader` (``0x48`` bytes);
* a 32-bit system header event whose payload is a ``TraceLogfileHeader`` plus the two
  logger/logfile names (the first record of every real ETL);
* one ``EVENT_HEADER32`` provider event carrying an arbitrary, fixed payload;
* ``0xFF`` padding up to the declared buffer size.

Only fixed-width primitive fields are used in the payload so the generated manifests do not
need the ``EtwPointer`` / ``UserSID_blob`` custom types, which keeps the reproduction independent
of an unrelated, pre-existing binding defect documented in ``README.md``.
"""

from __future__ import annotations

from uuid import UUID

from dissect.cstruct import cstruct
from dissect.etl.c_etl import c_etl

BUFFER_SIZE = 0x1000
BUFFER_HEADER_SIZE = 0x48

_TRACE_LOGFILE_DEF = """
struct SYSTEMTIME {
    WORD wYear; WORD wMonth; WORD wDayOfWeek; WORD wDay;
    WORD wHour; WORD wMinute; WORD wSecond; WORD wMilliseconds;
};
struct TZInfo {
    LONG Bias;
    wchar StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    wchar DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};
struct TraceLogfileHeader {
    uint32  BufferSize;
    uint32  Version;
    uint32  ProviderVersion;
    uint32  NumberOfProcessors;
    uint64  EndTime;
    uint32  TimerResolution;
    uint32  MaximumFileSize;
    uint32  LogFileMode;
    uint32  BuffersWritten;
    uint32  StartBuffers;
    uint32  PointerSize;
    uint32  EventsLost;
    uint32  CpuSpeedInMHz;
    uint32  LoggerNamePtr;
    uint32  LogFileNamePtr;
    TZInfo  TimeZone;
    uint32  padding;
    uint64  BootTime;
    uint64  PerfFreq;
    uint64  StartTime;
    uint32  ReservedFlags;
    uint32  BufferLost;
};
struct LogFileNames {
    wchar LoggerName[];
    wchar LogFileName[];
};
"""

_logfile_cstruct = cstruct().load("typedef uint32 PWSTR;" + _TRACE_LOGFILE_DEF)


def _align8(data: bytes) -> bytes:
    return data + b"\x00" * ((8 - len(data) % 8) % 8)


def _logfile_record(start_time: int, end_time: int) -> bytes:
    """Build the mandatory first record: a 32-bit system header + TraceLogfileHeader payload."""
    header = _logfile_cstruct.TraceLogfileHeader(
        BufferSize=BUFFER_SIZE,
        Version=0x00020001,
        ProviderVersion=0,
        NumberOfProcessors=1,
        EndTime=end_time,
        TimerResolution=1,
        MaximumFileSize=0,
        LogFileMode=0,
        BuffersWritten=1,
        StartBuffers=1,
        PointerSize=4,
        EventsLost=0,
        CpuSpeedInMHz=1000,
        LoggerNamePtr=0,
        LogFileNamePtr=0,
        BootTime=0,
        PerfFreq=10_000_000,
        StartTime=start_time,
        ReservedFlags=2,
        BufferLost=0,
    )
    names = _logfile_cstruct.LogFileNames(LoggerName="manifest-conflict-logger", LogFileName="synthetic.etl")
    payload = header.dumps() + names.dumps()

    record = c_etl.SystemHeader(
        Version=0,
        Marker=0xC001,
        Size=0x20 + len(payload),
        OpCode=0,
        Group=0,
        ThreadId=0,
        ProcessId=0,
        TimeDelta=0,
        ProcessorTime=0,
    ).dumps() + payload
    return _align8(record)


def provider_record(provider_guid: UUID, opcode: int, version: int, payload: bytes) -> bytes:
    """Build an aligned EVENT_HEADER32 record for ``provider_guid`` with ``payload``."""
    size = 0x50 + len(payload)
    header = c_etl.EventHeader(
        Size=size,
        Marker=0xC012,
        Flags=0,
        EventProperty=0,
        ThreadId=1234,
        ProcessId=5678,
        TimeDelta=10,
        ProviderId=provider_guid.bytes,
        Id=opcode,
        Version=version,
        Channel=11,
        Level=4,
        OpCode=opcode,
        Task=0,
        Keywords=0,
        ProcessorTime=0,
        ActivityId=b"\x00" * 16,
    )
    return _align8(header.dumps() + payload)


def build_etl(provider_guid: UUID, opcode: int, version: int, payload: bytes) -> bytes:
    """Return a complete, single-buffer 32-bit ETL file as bytes."""
    start_time = 132_586_490_800_000_000
    end_time = start_time + 10_000_000
    records = _logfile_record(start_time, end_time) + provider_record(provider_guid, opcode, version, payload)

    filled_bytes = BUFFER_HEADER_SIZE + len(records)
    buffer_header = c_etl.BufferHeader(
        BufferSize=BUFFER_SIZE,
        SavedOffset=filled_bytes,
        CurrentOffset=filled_bytes,
        ReferenceCounter=0,
        TimeDelta=0,
        SequenceNumber=0,
        Defined_1=0,
        ProcessorIndex=0,
        LoggerId=0,
        ETW_BUFFER_STATE=3,
        FilledBytes=filled_bytes,
        BufferFlag=c_etl.ETW_BUFFER_FLAG(0),
        BufferType=c_etl.ETW_BUFFER_TYPE(4),
        unk17=0,
        unk18=0,
        unk19=0,
        unk20=0,
    )
    blob = buffer_header.dumps() + records
    return blob + b"\xff" * (BUFFER_SIZE - len(blob))
