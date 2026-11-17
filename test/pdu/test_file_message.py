"""Bit Message Test Fixture.

This fixture tests the functionality of all the
bit based request/response messages:

* Read/Write Discretes
* Read Coils
"""

import pytest

from pymodbus.constants import ExcCodes
from pymodbus.datastore import (
    FileRecordStore,
    ModbusDeviceContext,
    ModbusServerContext,
)
from pymodbus.exceptions import FileRecordAccessError, ModbusException
from pymodbus.pdu.exceptionresponse import ExceptionResponse
from pymodbus.pdu.file_message import (
    FileRecord,
    ReadFifoQueueRequest,
    ReadFifoQueueResponse,
    ReadFileRecordRequest,
    ReadFileRecordResponse,
    WriteFileRecordRequest,
    WriteFileRecordResponse,
)


TEST_MESSAGE = b"\x00\n\x00\x04\x00\x01\x00\x02\x00\x03\x00\x04"


class DummyContext:
    """Minimal context exposing the file record store."""

    def __init__(self, store):
        """Initialize."""
        self.file_store = store


def make_store():
    """Build an in-memory store with two approved files."""
    store = FileRecordStore()
    store.add_file(14, first_record=10, record_count=10)
    store.add_file(15, first_record=0, record_count=100)
    return store


class TestBitMessage:
    """Modbus bit message tests."""

    def test_read_fifo_queue_request_encode(self):
        """Test basic bit message encoding/decoding."""
        handle = ReadFifoQueueRequest(0x1234)
        result = handle.x_encode()
        assert result == b"\x12\x34"

    def test_read_fifo_queue_request_decode(self):
        """Test basic bit message encoding/decoding."""
        handle = ReadFifoQueueRequest(0x0000)
        handle.x_decode(b"\x12\x34")
        assert handle.address == 0x1234

    async def test_read_fifo_queue_request(self, mock_server_context):
        """Test basic bit message encoding/decoding."""
        context = mock_server_context()
        handle = ReadFifoQueueRequest(0x1234)
        result = await handle.datastore_update(context, 0)
        assert isinstance(result, ReadFifoQueueResponse)

    def test_read_fifo_queue_response_encode(self):
        """Test that the read fifo queue response can encode."""
        message = TEST_MESSAGE
        handle = ReadFifoQueueResponse([1, 2, 3, 4])
        result = handle.x_encode()
        assert result == message

    def test_read_fifo_queue_response_decode(self):
        """Test that the read fifo queue response can decode."""
        message = TEST_MESSAGE
        handle = ReadFifoQueueResponse([1, 2, 3, 4])
        handle.x_decode(message)
        assert handle.values == [1, 2, 3, 4]

    def test_frame_size(self):
        """Test that the read fifo queue response can decode."""
        message = TEST_MESSAGE
        assert (
            ReadFifoQueueResponse.x_calculateRtuFrameSize(b"\x00\x18" + message) == 14
        )
        assert ReadFifoQueueRequest.x_calculateRtuFrameSize(b"") == 6

    # -----------------------------------------------------------------------#
    #  File Record
    # -----------------------------------------------------------------------#

    def test_file_record_length(self):
        """Test file record length generation."""
        record = FileRecord(
            file_number=0x01, record_number=0x02, record_data=b"\x00\x01\x02\x04"
        )
        assert record.record_length == 0x02

    def test_file_record_errors(self):
        """Test file record length generation."""
        with pytest.raises(ModbusException):
            FileRecord(record_length=12, record_data=b"\x00\x01\x02\x04")
        with pytest.raises(ModbusException):
            FileRecord(record_length=11)

    def test_read_file_record_request_encode(self):
        """Test basic bit message encoding/decoding."""
        records = [FileRecord(file_number=0x01, record_number=0x02)]
        handle = ReadFileRecordRequest(records=records)
        result = handle.x_encode()
        assert result == b"\x07\x06\x00\x01\x00\x02\x00\x00"

    def test_read_file_record_request_decode(self):
        """Test basic bit message encoding/decoding."""
        # record = FileRecord(file_number=0x04, record_number=0x01, record_length=0x02)
        request = b"\x0e\x06\x00\x04\x00\x01\x00\x02\x06\x00\x03\x00\x09\x00\x02"
        handle = ReadFileRecordRequest()
        handle.x_decode(request)
        # assert handle.records[0] == record

    def test_read_file_record_request_frame_size(self):
        """Test basic bit message encoding/decoding."""
        request = (
            b"\x00\x00\x0e\x06\x00\x04\x00\x01\x00\x02\x06\x00\x03\x00\x09\x00\x02"
        )
        handle = ReadFileRecordRequest()
        size = handle.x_calculateRtuFrameSize(request)
        assert size == 0x0E + 5

    async def test_read_file_record_request_datastore_update(self, mock_server_context):
        """Test basic bit message encoding/decoding."""
        context = mock_server_context()
        context.file_store = make_store()
        handle = ReadFileRecordRequest(
            [FileRecord(file_number=14, record_number=10, record_length=4)]
        )
        result = await handle.datastore_update(context, 0)
        assert isinstance(result, ReadFileRecordResponse)
        assert len(result.records) == 1
        assert result.records[0].record_length == 2
        assert result.records[0].record_data == b"\x00\x00\x00\x00"

    # -----------------------------------------------------------------------#
    #  Read File Record Response
    # -----------------------------------------------------------------------#

    def test_read_file_record_response_encode(self):
        """Test basic bit message encoding/decoding."""
        records = [FileRecord(record_data=b"\x00\x01\x02\x03\x04\x05")]
        handle = ReadFileRecordResponse(records)
        result = handle.x_encode()
        assert result == b"\x08\x07\x06\x00\x01\x02\x03\x04\x05"

    def test_read_file_record_response_decode(self):
        """Test basic bit message encoding/decoding."""
        # record1 = FileRecord(
        #     file_number=0x00, record_number=0x00, record_data=b"\x0d\xfe\x00\x20"
        # )
        # record2 = FileRecord(
        #     file_number=0x00, record_number=0x00, record_data=b"\x33\xcd\x00\x40"
        # )
        response = b"\x0c\x05\x06\x0d\xfe\x00\x20\x05\x06\x33\xcd\x00\x40"
        handle = ReadFileRecordResponse()
        handle.x_decode(response)

        # assert handle.records[0] == record1
        # ssert handle.records[1] == record2

    def test_read_file_record_response_frame_size(self):
        """Test basic bit message encoding/decoding."""
        request = b"\x00\x00\x0c\x05\x06\x0d\xfe\x00\x20\x05\x05\x06\x33\xcd\x00\x40"
        handle = ReadFileRecordResponse()
        size = handle.x_calculateRtuFrameSize(request)
        assert size == 0x0C + 5

    # -----------------------------------------------------------------------#
    #  Write File Record Request
    # -----------------------------------------------------------------------#

    def test_write_file_record_request_encode(self):
        """Test basic bit message encoding/decoding."""
        records = [
            FileRecord(
                file_number=0x01, record_number=0x02, record_data=b"\x00\x01\x02\x03"
            )
        ]
        handle = WriteFileRecordRequest(records)
        result = handle.x_encode()
        assert result == b"\x0b\x06\x00\x01\x00\x02\x00\x02\x00\x01\x02\x03"

    def test_write_file_record_request_decode(self):
        """Test basic bit message encoding/decoding."""
        # record = FileRecord(
        #     file_number=0x04,
        #     record_number=0x07,
        #     record_data=b"\x06\xaf\x04\xbe\x10\x0d",
        # )
        request = b"\x0d\x06\x00\x04\x00\x07\x00\x03\x06\xaf\x04\xbe\x10\x0d"
        handle = WriteFileRecordRequest()
        handle.x_decode(request)
        # assert handle.records[0] == record

    def test_write_file_record_request_frame_size(self):
        """Test write file record request rtu frame size calculation."""
        request = b"\x00\x00\x0d\x06\x00\x04\x00\x07\x00\x03\x06\xaf\x04\xbe\x10\x0d"
        handle = WriteFileRecordRequest()
        size = handle.x_calculateRtuFrameSize(request)
        assert size == 0x0D + 5

    async def test_write_file_record_request_datastore_update(
        self, mock_server_context
    ):
        """Test basic bit message encoding/decoding."""
        context = mock_server_context()
        context.file_store = make_store()
        handle = WriteFileRecordRequest(
            [
                FileRecord(
                    file_number=14,
                    record_number=10,
                    record_data=b"\x00\x01\x02\x03",
                )
            ]
        )
        result = await handle.datastore_update(context, 0)
        assert isinstance(result, WriteFileRecordResponse)
        assert result.records[0].record_data == b"\x00\x01\x02\x03"

    # -----------------------------------------------------------------------#
    #  Write File Record Response
    # -----------------------------------------------------------------------#

    def test_write_file_record_response_encode(self):
        """Test basic bit message encoding/decoding."""
        records = [
            FileRecord(
                file_number=0x01, record_number=0x02, record_data=b"\x00\x01\x02\x03"
            )
        ]
        handle = WriteFileRecordResponse(records)
        result = handle.x_encode()
        assert result == b"\x0b\x06\x00\x01\x00\x02\x00\x02\x00\x01\x02\x03"

    def test_write_file_record_response_decode(self):
        """Test basic bit message encoding/decoding."""
        # record = FileRecord(
        #     file_number=0x04,
        #     record_number=0x07,
        #     record_data=b"\x06\xaf\x04\xbe\x10\x0d",
        # )
        request = b"\x0d\x06\x00\x04\x00\x07\x00\x03\x06\xaf\x04\xbe\x10\x0d"
        handle = WriteFileRecordResponse()
        handle.x_decode(request)
        # assert handle.records[0] == record

    def test_read_file_record_request_decode_invalid_byte_count(self):
        """Test ReadFileRecordRequest raises ModbusException on oversized byte_count."""
        handle = ReadFileRecordRequest()
        with pytest.raises(ModbusException):
            handle.x_decode(bytes([0xFF, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01]))

    def test_write_file_record_request_decode_invalid_byte_count(self):
        """Test WriteFileRecordRequest raises ModbusException on oversized byte_count."""
        handle = WriteFileRecordRequest()
        with pytest.raises(ModbusException):
            handle.x_decode(
                bytes([0xFF, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])
            )

    def test_read_fifo_queue_response_decode_invalid_count(self):
        """Test ReadFifoQueueResponse raises ModbusException on oversized count."""
        handle = ReadFifoQueueResponse()
        with pytest.raises(ModbusException):
            handle.x_decode(bytes([0x00, 0x00, 0xFF, 0xFF]))

    def test_write_file_record_response_frame_size(self):
        """Test write file record response rtu frame size calculation."""
        request = b"\x00\x00\x0d\x06\x00\x04\x00\x07\x00\x03\x06\xaf\x04\xbe\x10\x0d"
        handle = WriteFileRecordResponse()
        size = handle.x_calculateRtuFrameSize(request)
        assert size == 0x0D + 5


class TestFileRecordStorePolicy:
    """Access approval policy for file record sub-requests."""

    def test_approved_intervals(self):
        """Test approved files expose the configured intervals."""
        store = make_store()
        assert store.files == {14: (10, 10), 15: (0, 100)}

    @pytest.mark.parametrize(
        ("first_record", "record_count"),
        [(-1, 10), (0x2710, 1), (10, 0)],
    )
    def test_add_file_rejects_bad_interval(self, first_record, record_count):
        """Test file intervals outside the Modbus range are refused."""
        store = FileRecordStore()
        with pytest.raises(ValueError, match="record"):
            store.add_file(1, first_record, record_count)

    def _record(self, file_number=14, record_number=10, length=2, ref=0x06, data=b""):
        record = FileRecord(
            file_number=file_number,
            record_number=record_number,
            reference_type=ref,
            record_data=data,
        )
        if not data:
            record.record_length = length
        return record

    def test_wrong_reference_type(self):
        """Test only the file reference type 0x06 is accepted."""
        store = make_store()
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records([self._record(ref=0x05)])
        assert exc.value.exception_code == ExcCodes.ILLEGAL_VALUE

    def test_wrong_length_zero_and_too_large(self):
        """Test record lengths outside 1..125 registers are refused."""
        store = make_store()
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records([self._record(length=0)])
        assert exc.value.exception_code == ExcCodes.ILLEGAL_VALUE
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records([self._record(length=126)])
        assert exc.value.exception_code == ExcCodes.ILLEGAL_VALUE

    def test_write_payload_length_mismatch(self):
        """Test a write payload not matching the register count is refused."""
        store = make_store()
        record = FileRecord(
            file_number=14, record_number=10, record_data=b"\x00\x01\x02\x03"
        )
        record.record_length = 3  # declares 3 registers but only carries 2
        with pytest.raises(FileRecordAccessError) as exc:
            store.write_records([record])
        assert exc.value.exception_code == ExcCodes.ILLEGAL_VALUE
        assert store._records[14] == {}

    def test_unknown_file(self):
        """Test unapproved file numbers raise ILLEGAL_ADDRESS."""
        store = make_store()
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records([self._record(file_number=99)])
        assert exc.value.exception_code == ExcCodes.ILLEGAL_ADDRESS

    def test_record_out_of_bounds(self):
        """Test a span crossing the approved interval is refused."""
        store = make_store()
        # file 14 covers records [10, 20); span [18, 21) crosses the edge
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records([self._record(record_number=18, length=3)])
        assert exc.value.exception_code == ExcCodes.ILLEGAL_ADDRESS

    def test_record_number_below_file_start(self):
        """Test record numbers before the approved start are refused."""
        store = make_store()
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records([self._record(record_number=9, length=1)])
        assert exc.value.exception_code == ExcCodes.ILLEGAL_ADDRESS

    def test_overlap_and_duplicate_rejected(self):
        """Test overlapping and identical sub-requests are refused."""
        store = make_store()
        overlapping = [
            self._record(record_number=10, length=3),
            self._record(record_number=11, length=2),
        ]
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records(overlapping)
        assert exc.value.exception_code == ExcCodes.ILLEGAL_VALUE
        duplicate = [
            self._record(record_number=10, length=2),
            self._record(record_number=10, length=2),
        ]
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records(duplicate)
        assert exc.value.exception_code == ExcCodes.ILLEGAL_VALUE

    def test_non_overlapping_and_cross_file_allowed(self):
        """Test adjacent spans and spans in different files coexist."""
        store = make_store()
        store.validate_records(
            [
                self._record(file_number=14, record_number=10, length=3),
                self._record(file_number=14, record_number=13, length=2),
                self._record(file_number=15, record_number=0, length=4),
            ]
        )

    def test_every_subrequest_validated_not_just_first(self):
        """Test a trailing bad sub-request fails even when the first is fine."""
        store = make_store()
        records = [
            self._record(record_number=10, length=2),
            self._record(record_number=13, length=2),
            self._record(record_number=18, length=3),  # crosses [10, 20)
        ]
        with pytest.raises(FileRecordAccessError) as exc:
            store.validate_records(records)
        assert exc.value.exception_code == ExcCodes.ILLEGAL_ADDRESS

    def test_total_bytes_lawful_does_not_save_oob_record(self):
        """Test a legal aggregate length cannot hide an out of bounds record."""
        store = make_store()
        records = [
            self._record(record_number=10, length=1),
            self._record(record_number=500, length=1),  # outside file 14
        ]
        with pytest.raises(FileRecordAccessError):
            store.validate_records(records)


class TestFileRecordStoreIO:
    """In-memory read/write behavior and atomicity."""

    async def test_read_two_valid_subrequests_preserves_order(self):
        """Test a legal batch reads back in request order."""
        store = make_store()
        store.write_records(
            [
                FileRecord(file_number=14, record_number=10, record_data=b"\x01\x02"),
                FileRecord(file_number=14, record_number=12, record_data=b"\x03\x04"),
            ]
        )
        request = ReadFileRecordRequest(
            [
                FileRecord(file_number=14, record_number=12, record_length=4),
                FileRecord(file_number=14, record_number=10, record_length=4),
            ]
        )
        for record in request.records:
            record.record_length //= 2
        context = DummyContext(store)
        result = await request.datastore_update(context, 0)
        assert isinstance(result, ReadFileRecordResponse)
        assert result.records[0].record_data == b"\x03\x04"
        assert result.records[1].record_data == b"\x01\x02"

    async def test_write_then_read_roundtrip(self):
        """Test written registers persist and unwritten ones read zero."""
        store = make_store()
        request = WriteFileRecordRequest(
            [
                FileRecord(
                    file_number=15, record_number=0, record_data=b"\xab\xcd\xef\x01"
                )
            ]
        )
        context = DummyContext(store)
        result = await request.datastore_update(context, 0)
        assert isinstance(result, WriteFileRecordResponse)
        assert store._records[15][0] == 0xABCD
        assert store._records[15][1] == 0xEF01
        read_request = ReadFileRecordRequest(
            [FileRecord(file_number=15, record_number=0, record_length=6)]
        )
        read_result = await read_request.datastore_update(context, 0)
        assert read_result.records[0].record_data == b"\xab\xcd\xef\x01\x00\x00"

    async def test_rejected_write_has_no_partial_write(self):
        """Test two valid plus one trailing OOB sub-request writes nothing."""

        class TrackingStore(FileRecordStore):
            """Store that records every register mutation."""

            def __init__(self):
                """Initialize."""
                super().__init__()
                self.add_file(14, first_record=10, record_count=10)
                self.mutations = 0

            def write_records(self, records):
                """Count batches that reach the actual storage write."""
                before = self.mutations
                super().write_records(records)
                self.mutations = before + 1

        store = TrackingStore()
        request = WriteFileRecordRequest(
            [
                FileRecord(file_number=14, record_number=10, record_data=b"\x00\x01"),
                FileRecord(file_number=14, record_number=12, record_data=b"\x00\x02"),
                FileRecord(
                    file_number=14,
                    record_number=18,
                    record_data=b"\x00\x03\x00\x04\x00\x05",
                ),
            ]
        )
        context = DummyContext(store)
        result = await request.datastore_update(context, 0)
        assert isinstance(result, ExceptionResponse)
        assert result.exception_code == ExcCodes.ILLEGAL_ADDRESS
        assert store.mutations == 0
        assert store._records[14] == {}

    async def test_rejected_read_does_not_touch_storage(self):
        """Test an invalid read batch returns an exception and no data."""
        store = make_store()
        store.write_records(
            [FileRecord(file_number=14, record_number=10, record_data=b"\x11\x11")]
        )
        request = ReadFileRecordRequest(
            [
                FileRecord(file_number=14, record_number=10, record_length=4),
                FileRecord(file_number=14, record_number=99, record_length=4),
            ]
        )
        for record in request.records:
            record.record_length //= 2
        context = DummyContext(store)
        result = await request.datastore_update(context, 0)
        assert isinstance(result, ExceptionResponse)
        assert result.exception_code == ExcCodes.ILLEGAL_ADDRESS
        assert all(record.record_data == b"" for record in request.records)
        assert store._records[14][10] == 0x1111

    async def test_missing_store_fails_closed(self):
        """Test contexts without an approved store reject file record access."""
        context = ModbusServerContext(devices=ModbusDeviceContext())
        read_result = await ReadFileRecordRequest().datastore_update(context, 0)
        assert isinstance(read_result, ExceptionResponse)
        assert read_result.exception_code == ExcCodes.ILLEGAL_ADDRESS
        write_result = await WriteFileRecordRequest().datastore_update(context, 0)
        assert isinstance(write_result, ExceptionResponse)
        assert write_result.exception_code == ExcCodes.ILLEGAL_ADDRESS

    async def test_wire_decode_keeps_register_count_and_reference_type(self):
        """Test decoded sub-requests keep the wire register count and type."""
        request = ReadFileRecordRequest()
        request.x_decode(
            b"\x0e\x06\x00\x0e\x00\x0a\x00\x02\x05\x00\x0f\x00\x00\x00\x01"
        )
        assert request.records[0].reference_type == 0x06
        assert request.records[0].file_number == 14
        assert request.records[0].record_number == 10
        assert request.records[0].record_length == 2
        assert request.records[1].reference_type == 0x05
        result = await request.datastore_update(DummyContext(make_store()), 0)
        assert isinstance(result, ExceptionResponse)
        assert result.exception_code == ExcCodes.ILLEGAL_VALUE
