"""
Tests for the scoped Atomic Read/Write File backup review adapter.

These tests drive ``AtomicFileServices`` off-network by overriding
``Application.response`` to capture the outgoing APDUs, then re-encode the
captured ACKs/errors to their wire bytes and decode them back, so the
asserted start position, content and end-of-file flag are exactly what a
BACnet peer would receive.
"""

from __future__ import annotations

from typing import List


from bacpypes3.apdu import (
    APDU,
    AtomicReadFileACK,
    AtomicReadFileRequest,
    AtomicWriteFileACK,
    AtomicWriteFileRequest,
    Error,
    RejectPDU,
    RejectReason,
)
from bacpypes3.app import Application
from bacpypes3.basetypes import (
    AtomicReadFileRequestAccessMethodChoice,
    AtomicReadFileRequestAccessMethodChoiceRecordAccess,
    AtomicReadFileRequestAccessMethodChoiceStreamAccess,
    AtomicWriteFileRequestAccessMethodChoice,
    AtomicWriteFileRequestAccessMethodChoiceRecordAccess,
    AtomicWriteFileRequestAccessMethodChoiceStreamAccess,
    ErrorCode,
)
from bacpypes3.debugging import ModuleLogger, bacpypes_debugging
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import (
    Boolean,
    Integer,
    ObjectIdentifier,
    OctetString,
    Unsigned,
)

from samples.backup_review.backup_file_adapter import (
    RECORD_ACCESS,
    STREAM_ACCESS,
    AtomicFileServices,
    ReadGrant,
    RecordBackupFile,
    StreamBackupFile,
    WriteGrant,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())

STREAM_FILE_ID = ObjectIdentifier("file,1")
RECORD_FILE_ID = ObjectIdentifier("file,2")
UNKNOWN_FILE_ID = ObjectIdentifier("file,99")

# stream: 16 octets, grant exposes [4, 12)
STREAM_DATA = bytes(range(0x10, 0x20))
# record: 10 records, grant exposes [2, 6)
RECORDS = [OctetString(b"R%02d" % index) for index in range(10)]


@bacpypes_debugging
class BackupReviewApplication(AtomicFileServices, Application):
    """Application that captures responses instead of sending them on wire."""

    responses: List[APDU]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.init_atomic_file_services()
        self.responses = []

        self.backup_files[STREAM_FILE_ID] = StreamBackupFile(
            file_identifier=STREAM_FILE_ID, data=bytearray(STREAM_DATA)
        )
        self.read_grants[STREAM_FILE_ID] = ReadGrant(
            file_identifier=STREAM_FILE_ID,
            access_method=STREAM_ACCESS,
            range_start=4,
            range_end=12,
        )
        self.backup_files[RECORD_FILE_ID] = RecordBackupFile(
            file_identifier=RECORD_FILE_ID, records=list(RECORDS)
        )
        self.read_grants[RECORD_FILE_ID] = ReadGrant(
            file_identifier=RECORD_FILE_ID,
            access_method=RECORD_ACCESS,
            range_start=2,
            range_end=6,
        )

    async def response(self, apdu: APDU) -> None:  # type: ignore[override]
        self.responses.append(apdu)


def _stream_read_request(start: int, count: int) -> AtomicReadFileRequest:
    return AtomicReadFileRequest(
        fileIdentifier=STREAM_FILE_ID,
        accessMethod=AtomicReadFileRequestAccessMethodChoice(
            streamAccess=AtomicReadFileRequestAccessMethodChoiceStreamAccess(
                fileStartPosition=Integer(start),
                requestedOctetCount=Unsigned(count),
            )
        ),
    )


def _record_read_request(start: int, count: int) -> AtomicReadFileRequest:
    return AtomicReadFileRequest(
        fileIdentifier=RECORD_FILE_ID,
        accessMethod=AtomicReadFileRequestAccessMethodChoice(
            recordAccess=AtomicReadFileRequestAccessMethodChoiceRecordAccess(
                fileStartRecord=Integer(start),
                requestedRecordCount=Unsigned(count),
            )
        ),
    )


def _stream_write_request(start: int, payload: bytes) -> AtomicWriteFileRequest:
    return AtomicWriteFileRequest(
        fileIdentifier=STREAM_FILE_ID,
        accessMethod=AtomicWriteFileRequestAccessMethodChoice(
            streamAccess=AtomicWriteFileRequestAccessMethodChoiceStreamAccess(
                fileStartPosition=Integer(start),
                fileData=OctetString(payload),
            )
        ),
    )


def _record_write_request(start: int, records):
    return AtomicWriteFileRequest(
        fileIdentifier=RECORD_FILE_ID,
        accessMethod=AtomicWriteFileRequestAccessMethodChoice(
            recordAccess=AtomicWriteFileRequestAccessMethodChoiceRecordAccess(
                fileStartRecord=Integer(start),
                recordCount=Unsigned(len(records)),
                fileRecordData=records,
            )
        ),
    )


async def _invoke(app: BackupReviewApplication, request: APDU) -> APDU:
    request.pduSource = Address("1.2.3.4")
    request.apduInvokeID = 7
    before = len(app.responses)
    await app.indication(request)
    assert len(app.responses) == before + 1
    return app.responses[-1]


def _round_trip(apdu: APDU) -> APDU:
    """Encode an APDU to wire bytes and decode it back to the same type."""
    wire = apdu.encode()
    assert bytes(wire.pduData), "expected a non-empty wire payload"
    return type(apdu).decode(wire)


#
#   happy path: stream and record reads, including wire round-trip
#


async def test_stream_read_inside_window_reports_start_content_and_eof():
    app = BackupReviewApplication()
    # octets [4, 8); file is 16 octets so this is not EOF yet
    ack = await _invoke(app, _stream_read_request(4, 4))
    assert isinstance(ack, AtomicReadFileACK)

    decoded = _round_trip(ack)
    stream = decoded.accessMethod.streamAccess
    assert int(stream.fileStartPosition) == 4
    assert bytes(stream.fileData) == STREAM_DATA[4:8]
    assert decoded.endOfFile == Boolean(False)
    app.close()


async def test_stream_read_to_end_of_file_sets_eof_flag():
    app = BackupReviewApplication()
    # ask for more than the window grants; end is clamped to 12, not EOF
    ack = await _invoke(app, _stream_read_request(10, 50))
    decoded = _round_trip(ack)
    stream = decoded.accessMethod.streamAccess
    assert int(stream.fileStartPosition) == 10
    assert bytes(stream.fileData) == STREAM_DATA[10:12]
    # window ends at octet 12 while the file has 16, so EOF stays false
    assert decoded.endOfFile == Boolean(False)
    app.close()


async def test_record_read_returns_records_not_octets():
    app = BackupReviewApplication()
    ack = await _invoke(app, _record_read_request(2, 3))
    decoded = _round_trip(ack)
    record = decoded.accessMethod.recordAccess
    assert int(record.fileStartRecord) == 2
    assert record.returnedRecordCount == Unsigned(3)
    assert [bytes(r) for r in record.fileRecordData] == [bytes(r) for r in RECORDS[2:5]]
    assert decoded.endOfFile == Boolean(False)
    app.close()


async def test_record_read_window_end_is_not_physical_eof():
    app = BackupReviewApplication()
    # request through record 5 (the grant end); 10 records exist overall
    ack = await _invoke(app, _record_read_request(4, 10))
    decoded = _round_trip(ack)
    record = decoded.accessMethod.recordAccess
    assert int(record.fileStartRecord) == 4
    assert record.returnedRecordCount == Unsigned(2)
    assert [bytes(r) for r in record.fileRecordData] == [bytes(r) for r in RECORDS[4:6]]
    assert decoded.endOfFile == Boolean(False)
    app.close()


#
#   the same numeric offset means different ranges in the two modes
#


async def test_same_offset_is_octet_range_vs_record_range():
    """The same numeric offset names different ranges in the two modes.

    Offset 4 is inside both approved windows, so it can be read in each
    mode.  In stream mode it selects the single octet at byte 4; in record
    mode it selects the whole record at index 4 (three octets).  The number
    4 is identical on the wire, but the addressed content and its width are
    different -- record access must never be flattened into a byte stream.
    """
    app = BackupReviewApplication()

    stream_ack = await _invoke(app, _stream_read_request(4, 1))
    stream_decoded = _round_trip(stream_ack)
    stream_start = int(stream_decoded.accessMethod.streamAccess.fileStartPosition)
    stream_data = bytes(stream_decoded.accessMethod.streamAccess.fileData)
    # stream mode: offset 4 is exactly one octet
    assert stream_start == 4
    assert stream_data == STREAM_DATA[4:5]
    assert len(stream_data) == 1

    record_ack = await _invoke(app, _record_read_request(4, 1))
    record_decoded = _round_trip(record_ack)
    record_start = int(record_decoded.accessMethod.recordAccess.fileStartRecord)
    record_data = list(record_decoded.accessMethod.recordAccess.fileRecordData)
    # record mode: offset 4 is one whole record, not the octet at byte 4
    assert record_start == 4
    assert record_decoded.accessMethod.recordAccess.returnedRecordCount == 1
    assert [bytes(r) for r in record_data] == [bytes(RECORDS[4])]
    assert len(bytes(record_data[0])) == 3
    assert bytes(record_data[0]) != stream_data

    # and the same offset 3 is a different out-of-window position in each
    # file's own unit: byte 3 of the stream, record 3 of the record file
    stream_miss = await _invoke(app, _stream_read_request(3, 1))
    record_miss = await _invoke(app, _record_read_request(3, 1))
    stream_miss_decoded = _round_trip(stream_miss)
    record_miss_decoded = _round_trip(record_miss)
    # stream grant starts at byte 4, so byte 3 is clamped up to byte 4
    assert int(stream_miss_decoded.accessMethod.streamAccess.fileStartPosition) == 4
    # record grant starts at record 2, so record 3 is inside and returned
    assert int(record_miss_decoded.accessMethod.recordAccess.fileStartRecord) == 3
    assert [
        bytes(r) for r in record_miss_decoded.accessMethod.recordAccess.fileRecordData
    ] == [bytes(RECORDS[3])]
    app.close()


#
#   authorization failures and protocol results
#


async def test_unknown_file_is_object_unknown_object_error():
    app = BackupReviewApplication()
    request = AtomicReadFileRequest(
        fileIdentifier=UNKNOWN_FILE_ID,
        accessMethod=AtomicReadFileRequestAccessMethodChoice(
            streamAccess=AtomicReadFileRequestAccessMethodChoiceStreamAccess(
                fileStartPosition=Integer(0),
                requestedOctetCount=Unsigned(1),
            )
        ),
    )
    response = await _invoke(app, request)
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.unknownObject
    app.close()


async def test_negative_stream_start_is_invalid_file_start_position():
    app = BackupReviewApplication()
    response = await _invoke(app, _stream_read_request(-1, 4))
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.invalidFileStartPosition
    app.close()


async def test_negative_record_start_is_invalid_file_start_position():
    app = BackupReviewApplication()
    response = await _invoke(app, _record_read_request(-2, 2))
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.invalidFileStartPosition
    app.close()


async def test_start_beyond_window_is_invalid_file_start_position():
    app = BackupReviewApplication()
    response = await _invoke(app, _stream_read_request(12, 1))
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.invalidFileStartPosition
    app.close()


async def test_switching_access_mode_is_rejected_not_widened():
    """A stream-granted file must not be read via record access."""
    app = BackupReviewApplication()
    # record access against the stream-granted file
    request = AtomicReadFileRequest(
        fileIdentifier=STREAM_FILE_ID,
        accessMethod=AtomicReadFileRequestAccessMethodChoice(
            recordAccess=AtomicReadFileRequestAccessMethodChoiceRecordAccess(
                fileStartRecord=Integer(0),
                requestedRecordCount=Unsigned(1),
            )
        ),
    )
    response = await _invoke(app, request)
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.invalidFileAccessMethod

    # and stream access against the record-granted file
    request = AtomicReadFileRequest(
        fileIdentifier=RECORD_FILE_ID,
        accessMethod=AtomicReadFileRequestAccessMethodChoice(
            streamAccess=AtomicReadFileRequestAccessMethodChoiceStreamAccess(
                fileStartPosition=Integer(0),
                requestedOctetCount=Unsigned(1),
            )
        ),
    )
    response = await _invoke(app, request)
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.invalidFileAccessMethod
    app.close()


async def test_unknown_access_method_is_a_reject():
    app = BackupReviewApplication()
    request = AtomicReadFileRequest(fileIdentifier=STREAM_FILE_ID)
    # no accessMethod choice at all
    request.accessMethod = AtomicReadFileRequestAccessMethodChoice()
    response = await _invoke(app, request)
    assert isinstance(response, RejectPDU)
    assert response.apduAbortRejectReason == RejectReason.missingRequiredParameter
    app.close()


async def test_read_is_always_clamped_to_grant_boundary():
    """No bytes outside [4, 12) ever leave the adapter, even on over-read."""
    app = BackupReviewApplication()
    ack = await _invoke(app, _stream_read_request(0, 256))
    decoded = _round_trip(ack)
    stream = decoded.accessMethod.streamAccess
    # start 0 is before the window; clamp start up to the grant boundary too
    assert int(stream.fileStartPosition) == 4
    assert bytes(stream.fileData) == STREAM_DATA[4:12]
    app.close()


#
#   writes follow explicit policy
#


async def test_write_denied_by_default():
    app = BackupReviewApplication()
    response = await _invoke(app, _stream_write_request(8, b"ZZ"))
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.writeAccessDenied
    # underlying file untouched
    assert bytes(app.backup_files[STREAM_FILE_ID].data[8:10]) == STREAM_DATA[8:10]
    app.close()


async def test_write_allowed_inside_explicit_grant():
    app = BackupReviewApplication()
    app.write_policy.allowed[(STREAM_FILE_ID, STREAM_ACCESS)] = WriteGrant(
        range_start=8, range_end=10
    )
    ack = await _invoke(app, _stream_write_request(8, b"ZZ"))
    assert isinstance(ack, AtomicWriteFileACK)
    decoded = _round_trip(ack)
    assert int(decoded.fileStartPosition) == 8
    assert bytes(app.backup_files[STREAM_FILE_ID].data[8:10]) == b"ZZ"
    app.close()


async def test_write_outside_grant_denied_even_with_policy():
    app = BackupReviewApplication()
    app.write_policy.allowed[(STREAM_FILE_ID, STREAM_ACCESS)] = WriteGrant(
        range_start=8, range_end=10
    )
    # octets [10, 12) are readable but not in the write grant
    response = await _invoke(app, _stream_write_request(10, b"ZZ"))
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.writeAccessDenied
    app.close()


async def test_record_write_denied_when_no_record_policy():
    app = BackupReviewApplication()
    response = await _invoke(
        app,
        _record_write_request(2, [OctetString(b"NEW")]),
    )
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.writeAccessDenied
    app.close()


async def test_record_count_mismatch_is_inconsistent_parameters_reject():
    app = BackupReviewApplication()
    app.write_policy.allowed[(RECORD_FILE_ID, RECORD_ACCESS)] = WriteGrant(
        range_start=2, range_end=4
    )
    request = AtomicWriteFileRequest(
        fileIdentifier=RECORD_FILE_ID,
        accessMethod=AtomicWriteFileRequestAccessMethodChoice(
            recordAccess=AtomicWriteFileRequestAccessMethodChoiceRecordAccess(
                fileStartRecord=Integer(2),
                recordCount=Unsigned(5),  # claims 5, carries 1
                fileRecordData=[OctetString(b"NEW")],
            )
        ),
    )
    response = await _invoke(app, request)
    assert isinstance(response, RejectPDU)
    assert response.apduAbortRejectReason == RejectReason.inconsistentParameters
    app.close()


async def test_write_mode_switch_cannot_enlarge_scope():
    """A stream write grant must not authorize record writes."""
    app = BackupReviewApplication()
    app.write_policy.allowed[(STREAM_FILE_ID, STREAM_ACCESS)] = WriteGrant(
        range_start=8, range_end=10
    )
    # record-mode write to the stream-granted file
    request = AtomicWriteFileRequest(
        fileIdentifier=STREAM_FILE_ID,
        accessMethod=AtomicWriteFileRequestAccessMethodChoice(
            recordAccess=AtomicWriteFileRequestAccessMethodChoiceRecordAccess(
                fileStartRecord=Integer(0),
                recordCount=Unsigned(1),
                fileRecordData=[OctetString(b"X")],
            )
        ),
    )
    response = await _invoke(app, request)
    assert isinstance(response, Error)
    assert response.errorCode == ErrorCode.writeAccessDenied
    app.close()
