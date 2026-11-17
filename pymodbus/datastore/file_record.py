"""In-memory file record storage with access approval checks.

The Modbus file record functions (Read File Record 0x14 and Write File
Record 0x15) carry several independent sub-requests inside one PDU.  Every
sub-request addresses a span of registers inside a file and the server must
prove that *all* spans are inside an approved file/record interval before a
single byte is read or written.  Checking only the first sub-request, or
checking the aggregate byte count, is explicitly not sufficient.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..constants import ExcCodes
from ..exceptions import FileRecordAccessError


if TYPE_CHECKING:
    from ..pdu.file_message import FileRecord

REFERENCE_TYPE_FILE = 0x06
MIN_RECORD_NUMBER = 0x0000
MAX_RECORD_NUMBER = 0x270F
MAX_RECORD_LENGTH = 0x007D


class FileRecordStore:
    """Memory backed storage for Modbus file records.

    Each approved file is described by ``(first_record, record_count)``.
    Records are addressed from ``first_record`` and a file therefore covers
    the half-open interval ``[first_record, first_record + record_count)``.

    Record data is kept as a mapping of register numbers to 16-bit values.
    Registers that were never written read back as ``0``.
    """

    def __init__(self, files: dict[int, tuple[int, int]] | None = None) -> None:
        """Define the approved files and (optionally) seed storage."""
        self.files: dict[int, tuple[int, int]] = dict(files or {})
        self._records: dict[int, dict[int, int]] = {
            file_number: {} for file_number in self.files
        }

    def add_file(self, file_number: int, first_record: int, record_count: int) -> None:
        """Approve an additional file interval."""
        if not MIN_RECORD_NUMBER <= first_record <= MAX_RECORD_NUMBER:
            raise ValueError(
                f"first_record {first_record} outside "
                f"[0x{MIN_RECORD_NUMBER:04x}, 0x{MAX_RECORD_NUMBER:04x}]"
            )
        if record_count < 1:
            raise ValueError("record_count must be >= 1")
        if first_record + record_count - 1 > MAX_RECORD_NUMBER:
            raise ValueError(
                f"file {file_number} extends past record 0x{MAX_RECORD_NUMBER:04x}"
            )
        self.files[file_number] = (first_record, record_count)
        self._records.setdefault(file_number, {})

    def validate_records(
        self, records: list[FileRecord], *, data_required: bool = False
    ) -> None:
        """Validate every sub-request before any storage access.

        The whole batch is rejected when a single sub-request is invalid,
        so callers never observe a partially validated/processed request.

        Policies:

        * reference type must be 0x06 (file reference);
        * record length must be 1..125 registers (wrong length -> ILLEGAL_VALUE);
        * when ``data_required`` is set (write requests) the payload must
          contain exactly record_length * 2 bytes (ILLEGAL_VALUE);
        * file number must belong to the approved files (ILLEGAL_ADDRESS);
        * record number and the complete span must lie inside the approved
          interval (out of bounds -> ILLEGAL_ADDRESS);
        * duplicate sub-requests and overlapping spans are rejected
          (ILLEGAL_VALUE).
        """
        seen_intervals: list[tuple[int, int, int]] = []
        for index, record in enumerate(records):
            prefix = f"sub-request {index}"
            if record.reference_type != REFERENCE_TYPE_FILE:
                raise FileRecordAccessError(
                    ExcCodes.ILLEGAL_VALUE,
                    f"{prefix}: reference type 0x{record.reference_type:02x} "
                    f"is not 0x{REFERENCE_TYPE_FILE:02x}",
                )
            if not 1 <= record.record_length <= MAX_RECORD_LENGTH:
                raise FileRecordAccessError(
                    ExcCodes.ILLEGAL_VALUE,
                    f"{prefix}: record length {record.record_length} outside "
                    f"[1, {MAX_RECORD_LENGTH}]",
                )
            if data_required and len(record.record_data) != record.record_length * 2:
                raise FileRecordAccessError(
                    ExcCodes.ILLEGAL_VALUE,
                    f"{prefix}: payload of {len(record.record_data)} bytes does "
                    f"not match record length {record.record_length}",
                )
            if record.file_number not in self.files:
                raise FileRecordAccessError(
                    ExcCodes.ILLEGAL_ADDRESS,
                    f"{prefix}: file number {record.file_number} is not approved",
                )
            first_record, record_count = self.files[record.file_number]
            start = record.record_number
            end = start + record.record_length
            if (
                not MIN_RECORD_NUMBER <= start <= MAX_RECORD_NUMBER
                or start < first_record
                or end > first_record + record_count
            ):
                raise FileRecordAccessError(
                    ExcCodes.ILLEGAL_ADDRESS,
                    f"{prefix}: records [{start}, {end}) of file "
                    f"{record.file_number} exceed approved interval "
                    f"[{first_record}, {first_record + record_count})",
                )
            for seen_file, seen_start, seen_end in seen_intervals:
                if (
                    seen_file == record.file_number
                    and start < seen_end
                    and seen_start < end
                ):
                    raise FileRecordAccessError(
                        ExcCodes.ILLEGAL_VALUE,
                        f"{prefix}: records [{start}, {end}) of file "
                        f"{record.file_number} overlap an earlier sub-request "
                        f"[{seen_start}, {seen_end})",
                    )
            seen_intervals.append((record.file_number, start, end))

    def read_records(self, records: list[FileRecord]) -> list[bytes]:
        """Return record data in the same order as the sub-requests."""
        self.validate_records(records)
        result: list[bytes] = []
        for record in records:
            stored = self._records[record.file_number]
            start = record.record_number
            result.append(
                b"".join(
                    stored.get(start + offset, 0).to_bytes(2, "big")
                    for offset in range(record.record_length)
                )
            )
        return result

    def write_records(self, records: list[FileRecord]) -> None:
        """Validate first, then write all sub-requests without partial writes."""
        self.validate_records(records, data_required=True)
        for record in records:
            stored = self._records[record.file_number]
            start = record.record_number
            for offset in range(record.record_length):
                data_index = offset * 2
                stored[start + offset] = int.from_bytes(
                    record.record_data[data_index : data_index + 2], "big"
                )
